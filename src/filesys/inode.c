#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t start; /* First data sector. */
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  uint32_t unused[125]; /* Not used. */
};

// 2 way, 2 offset, 16 index
// 0 offset, 1-4 index, other tags
// tags, 4 index, 1 offset
// table*[16][2] -> malloc
// {uint32_t tags,
// bool valid, dirty;
// metadata (int age; lock use),
// data*[2] -> (malloc uint8_t[BLOCK_SECTOR_SIZE]) }

// read: table [(address>>1) & 0xf]
// for i:
//  hold use
//  if t[i].valid &
//      t[i].tags == address >> 5
//   hit:
//   read from memory t[i] -> data[address&1]
//  release use
// else miss:
//  goto replace
//  hold use
//   read from memory t[i] -> data[address&1]
//  release use

// write: same as read, yet
// hit:
// write to mem, set dirty

// replace:
// get index, tags
// c=alg_to_replace
//  hold c.use
//  if c.valid & c.dirty: write to disk
//  set tags = address>>5, dirty=f
//  age=age_cnt++
//  read two data
//  release c.use

// alg LRU
// meta: age bits, valid, dirty, use(sema, for r&w)
struct page_cache_way {
  uint32_t tags;
  bool valid;
  bool dirty;
  uint32_t age; // large enough (1 years?)
  struct lock use;
  // --- meta data ---
  uint8_t* data[2];
};

static struct page_cache_way* page_cache;
static uint32_t page_cache_age_count = 0;

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  page_cache = malloc(sizeof(struct page_cache_way)*16*2);
  ASSERT(page_cache != NULL);
  for (int i = 0; i < 32; i++) {
    page_cache[i].valid = false;
    lock_init(&page_cache[i].use);
    page_cache[i].data[0] = malloc(BLOCK_SECTOR_SIZE);
    ASSERT(page_cache[i].data[0] != NULL);
    page_cache[i].data[1] = malloc(BLOCK_SECTOR_SIZE);
    ASSERT(page_cache[i].data[1] != NULL);
  }
}

void inode_done(void) {
  for (int i = 0; i < 32; i++) {
    if (page_cache[i].valid && page_cache[i].dirty) {
      block_write(fs_device, (page_cache[i].tags<<5)+(i&(~1)), page_cache[i].data[0]);
      block_write(fs_device, (page_cache[i].tags<<5)+(i|1), page_cache[i].data[1]);
    }
    free(page_cache[i].data[0]);
    free(page_cache[i].data[1]);
  }
  free(page_cache);
}

// requirement:
// extend the size of files (& dirs) (unix fs)
// (support open, write, close...)
// inumber (= sector)
// no external fragmentation (unix fs)
// Implement file growth
// error return

// sreuct inode_disk: (inode data)
// inode_disk start, len, magic.
// block_sector_t block[120]
// block_sector_t indirect[4]
// block_sector_t d_indirect
// filesize(max) = 512B* (120+128*4+128*128)
// len will determain the valid of the block

// struct indirect pointer:
// block_sector_t(u32) [BLOCK_SECTOR_SIZE/4(128)]

// byte_to_sector(ofs):
// ofs/512 -> sector_ofs
// if sector_ofs < 120: read inode.sector, get block[sector]
// sector_ofs -= 120
// else if sector_ofs < 128*4
//   read inode.sector, get indirect[(sector_ofs)/128]
//   read indirect -> buffer, get *(buffer + sector_ofs%128)
// sector_ofs -= 128*4
// else
//   read inode.sector, get d_indirect
//   read d_indirect -> buffer, get *(buffer + sector_ofs/128)
//   read it -> buffer, get *(buffer + sector%128)

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    if (free_map_allocate(sectors, &disk_inode->start)) {
      block_write(fs_device, sector, disk_inode);
      if (sectors > 0) {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        for (i = 0; i < sectors; i++)
          block_write(fs_device, disk_inode->start + i, zeros);
      }
      success = true;
    }
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

static struct page_cache_way* page_cache_get_cache(block_sector_t address) {
  // tags, 4 index, 1 offset
  // get the middle index, and *2 for two ways
  struct page_cache_way* cache = page_cache+((address>>1)&0xf)*2;
  for (int i = 0; i < 2; i++) {
    lock_acquire(&cache->use);
    if (cache->valid && cache->tags == address>>5)
      return cache; // release the lock out of function
    lock_release(&cache->use);
    cache ++;
  }
  return NULL;
}

static struct page_cache_way* page_cache_replace_cache(block_sector_t address) {
  // tags, 4 index, 1 offset
  // get the middle index, and *2 for two ways
  struct page_cache_way* cache = page_cache+((address>>1)&0xf)*2;
  // STUB: since we only have two ways
  lock_acquire(&cache->use);
  lock_acquire(&(cache+1)->use);
  if (cache->valid && (cache+1)->valid) {
    if (cache->age <= (cache+1)->age) {
      lock_release(&(cache+1)->use);
    } else {
      lock_release(&cache->use);
      cache ++;
    }
  } else {
    if (!cache->valid) {
      lock_release(&(cache + 1)->use);
    } else {
      lock_release(&cache->use);
      cache++;
    }
  }

  if (cache->valid && cache->dirty) {
    // tags, 4 index, 1 offset
    block_write(fs_device, (cache->tags<<5)+(address&0x1e), cache->data[0]);
    block_write(fs_device, (cache->tags<<5)+(address&0x1e)+1, cache->data[1]);
  }
  cache->tags = address>>5;
  cache->dirty = false;
  cache->valid = true;
  cache->age = page_cache_age_count ++;
  block_read(fs_device, address&(~1), cache->data[0]);
  block_read(fs_device, address|1, cache->data[1]);
  return cache;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;
    struct page_cache_way* cache = page_cache_get_cache(sector_idx);
    if (cache == NULL) // miss
      cache = page_cache_replace_cache(sector_idx);
    memcpy(buffer + bytes_read, cache->data[sector_idx&1] + sector_ofs, chunk_size);
    lock_release(&cache->use);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    struct page_cache_way* cache = page_cache_get_cache(sector_idx);
    if (cache == NULL) // miss
      cache = page_cache_replace_cache(sector_idx);
    cache->dirty = true;
    memcpy(cache->data[sector_idx&1] + sector_ofs, buffer + bytes_written, chunk_size);
    lock_release(&cache->use);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }
