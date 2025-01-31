#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "bitmap.h"
#include "devices/block.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/off_t.h"
#include "stddef.h"
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
  block_sector_t block[120];
  block_sector_t indirect[4];
  block_sector_t dindirect;
};

struct page_cache_way {
  uint32_t tags;
  bool valid;
  bool dirty;
  uint32_t age; // large enough (1 years?)
  struct lock use;
  // --- meta data end ---
  uint8_t* data[2];
};

static struct page_cache_way* page_cache;
static uint32_t page_cache_age_count = 0;

static struct page_cache_way* page_cache_get_cache(block_sector_t address);
static struct page_cache_way* page_cache_replace_cache(block_sector_t address);
static void cache_read(block_sector_t sector_idx, off_t sector_ofs, void* buffer, size_t size);
static void cache_write(block_sector_t sector_idx, off_t sector_ofs, const void* buffer, size_t size);
static inline void read_sector(block_sector_t sector, void* buffer);
static inline void write_sector(block_sector_t sector, const void* buffer);

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct lock inode_lock;
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  void* block = malloc(BLOCK_SECTOR_SIZE);
  int sector;

  if (block == NULL) return SECTOR_ERROR;
  read_sector(inode->sector, block);
  if (pos >= ((struct inode_disk*)block)->length) {
    free(block);
    return SECTOR_ERROR;
  }
  pos /= BLOCK_SECTOR_SIZE;
  if (pos < 120) {
    sector = ((struct inode_disk*)block)->block[pos];
    free(block);
    return sector;
  } // else indirect
  pos -= 120;
  if (pos < 128*4) {
    read_sector(((struct inode_disk*)block)->indirect[pos/128], block);
    sector = ((block_sector_t*)block)[pos%128];
    free(block);
    return sector;
  } // else double indirect
  pos -= 128*4;
  if (pos < 128*128) {
    read_sector(((struct inode_disk*)block)->dindirect, block);
    read_sector(((block_sector_t*)block)[pos/128], block);
    sector = ((block_sector_t*)block)[pos%128];
    free(block);
    return sector;
  }
  NOT_REACHED();
}

static inline bool alloc_restore(block_sector_t* i, void* old) {
  if (!free_map_allocate(1, i)) {
    free_map_restore(old);
    free(old);
    return true;
  }
  return false;
}

static bool extend_inode(struct inode_disk* block, off_t len) {
  if (len <= 0) return true; // success doing nothing
  void* freemap_old = free_map_backup();
  for (block_sector_t i = block->length-1<0 ? 0 : (block->length-1)/BLOCK_SECTOR_SIZE+1; //rounddown+1
       i < (block_sector_t)(block->length+len-1)/BLOCK_SECTOR_SIZE+1; i ++) {
    block_sector_t ofs = i;
    if (i < 120) {
      if (alloc_restore(&block->block[i], freemap_old))
        return false;
      static char zeros[BLOCK_SECTOR_SIZE];
      block_write(fs_device, block->block[i], zeros);
      continue;
    }
    ofs -= 120;
    if (ofs < 128 * 4) {
      block_sector_t indirect[128];
      if (ofs % 128 == 0) { //first pointer
        if (alloc_restore(&block->indirect[ofs / 128], freemap_old))
          return false;
      } else {
        read_sector(block->indirect[ofs / 128], &indirect);
      }
      if (alloc_restore(&indirect[ofs%128], freemap_old))
        return false;
      write_sector(block->indirect[ofs/128], &indirect);
      continue;
    }
    ofs -= 128*4;
    block_sector_t dindirect[128];
    block_sector_t indirect[128];
    if (ofs == 0) {
      if (alloc_restore(&block->dindirect, freemap_old))
        return false;
    } else {
      read_sector(block->dindirect, &dindirect);
    }
    if (ofs % 128 == 0) {
      if (alloc_restore(&dindirect[ofs/128], freemap_old))
        return false;
    } else {
      read_sector(dindirect[ofs/128], &indirect);
    }
    if (alloc_restore(&indirect[ofs%128], freemap_old))
      return false;
    write_sector(dindirect[ofs/128], &indirect);
    write_sector(block->dindirect, &dindirect);
  }
  free(freemap_old);
  block->length += len;
  return true;
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
    disk_inode->length = 0;
    disk_inode->start = sector;
    disk_inode->magic = INODE_MAGIC;
    if (extend_inode(disk_inode, length)) {
      write_sector(sector, disk_inode);
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
  lock_init(&inode->inode_lock);
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
bool inode_is_removed(const struct inode* inode) { return inode->removed; }

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
      struct inode_disk block;
      read_sector(inode->sector, &block);

      for (int i = 0; i < block.length; i += 512) {
        block_sector_t sector = byte_to_sector(inode, i);
        ASSERT(sector != SECTOR_ERROR);
        free_map_release(sector, 1);
      }
      if (block.length >= 120*BLOCK_SECTOR_SIZE)
        for (int i = 0; i <= (block.length-120)/128; i ++)
          free_map_release(block.indirect[i], 1);
      if (block.length >= (120+128*4)*BLOCK_SECTOR_SIZE) {
        block_sector_t dindirect[128];
        read_sector(block.dindirect, &dindirect);
        for (int i = 0; i <= (block.length-120-128*4)/128; i ++)
          free_map_release(dindirect[i], 1);
        free_map_release(block.dindirect, 1);
      }
      free_map_release(inode->sector, 1);
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

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  lock_acquire(&inode->inode_lock);
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    if (sector_idx == SECTOR_ERROR) break;
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    cache_read(sector_idx, sector_ofs, buffer+bytes_read, chunk_size);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  lock_release(&inode->inode_lock);

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

  lock_acquire(&inode->inode_lock);
  struct inode_disk block;
  read_sector(inode->sector, &block);
  extend_inode(&block, size+offset-block.length);
  write_sector(inode->sector, &block);

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

    cache_write(sector_idx, sector_ofs, buffer + bytes_written, chunk_size);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  lock_release(&inode->inode_lock);
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
off_t inode_length(const struct inode* inode) {
  struct inode_disk block;
  read_sector(inode->sector, &block);
  return block.length;
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
  // STUB: compare and get lock, but since we only have two ways
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

static void cache_read
(block_sector_t sector_idx, off_t sector_ofs, void* buffer, size_t size) {
  struct page_cache_way* cache = page_cache_get_cache(sector_idx);
  if (cache == NULL) // miss
    cache = page_cache_replace_cache(sector_idx);
  memcpy(buffer, cache->data[sector_idx&1] + sector_ofs, size);
  lock_release(&cache->use);
}

static void cache_write
(block_sector_t sector_idx, off_t sector_ofs, const void* buffer, size_t size) {
  struct page_cache_way* cache = page_cache_get_cache(sector_idx);
  if (cache == NULL) // miss
    cache = page_cache_replace_cache(sector_idx);
  cache->dirty = true;
  memcpy(cache->data[sector_idx&1] + sector_ofs, buffer, size);
  lock_release(&cache->use);
}

static inline void read_sector(block_sector_t sector, void* buffer) {
  cache_read(sector, 0, buffer, BLOCK_SECTOR_SIZE);
}
static inline void write_sector(block_sector_t sector, const void* buffer) {
  cache_write(sector, 0, buffer, BLOCK_SECTOR_SIZE);
}
