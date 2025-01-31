#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();
  thread_current()->pcb->cwd = dir_open_root();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  inode_done();
  free_map_close();
}

static struct dir* filesys_lookup(char last_part[NAME_MAX+1], const char* name) {
  struct dir* dir;
  struct inode* inode;
  memset(last_part, 0, sizeof(char) * (NAME_MAX+1));
  char* dst = last_part;
  if (name[0] == '/') {
    dir = dir_open_root();
  } else {
    lock_acquire(&thread_current()->pcb->pcb_lock);
    dir = dir_reopen(thread_current()->pcb->cwd);
    lock_release(&thread_current()->pcb->pcb_lock);
  }

  bool mark = false;
  while (true) {
    while (*name == '/')
      name++;
    if (*name == '\0')
      return dir;

    if (mark) {
      if (dir == NULL) return NULL;
      if (!dir_lookup(dir, last_part, &inode)) {
        inode_close(inode);
        dir_close(dir);
        return NULL;
      }
      dir_close(dir);
      dir = dir_open(inode);
    } else mark = true;// not to do this section for first time

    dst = last_part;
    /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
    while (*name != '/' && *name != '\0') {
      if (dst < last_part + NAME_MAX)
        *dst++ = *name;
      else
        {dir_close(dir); return NULL;}
      name++;
    }
    *dst = '\0';
  }
  NOT_REACHED();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
static bool filesys_create_helper(const char* name_, off_t initial_size, bool is_dir) {
  block_sector_t inode_sector = 0;
  char name[NAME_MAX+1];
  struct dir* dir = filesys_lookup(name, name_);
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  (is_dir ?
                   dir_create(inode_sector, dir, 0) :
                   inode_create(inode_sector, initial_size))
                  && dir_add(dir, name, inode_sector, is_dir));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}
bool filesys_create(const char* name_, off_t initial_size) {
  return filesys_create_helper(name_, initial_size, false);
}
bool filesys_create_dir(const char* name){
  return filesys_create_helper(name, 0, true);
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_open(void* file, const char* name_) {
  char name[NAME_MAX+1];
  if (!strcmp(name_, "/")) {
    *(struct dir**)file = dir_open_root();
    return true;
  }
  struct dir* dir = filesys_lookup(name, name_);
  struct inode* inode = NULL;
  bool is_dir = false;

  if (dir != NULL)
    is_dir = dir_lookup(dir, name, &inode);
  dir_close(dir);

  if (is_dir)
    *(struct dir**)file = dir_open(inode);
  else
    *(struct file**)file = file_open(inode);
  return is_dir;
}

struct file* filesys_open_file(const char* name) {
  struct file* f;
  if (!filesys_open(&f, name))
    return f;
  else
    return NULL;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name_) {
  char name[NAME_MAX+1];
  struct dir* dir = filesys_lookup(name, name_);
  struct inode* inode;
  if (name[0] == '\0') return false;
  bool success = dir != NULL;
  if (success) {
    if (dir_lookup(dir, name, &inode)) { // is dir
      struct dir* d = dir_open(inode);
      if (dir_has_file(d)) { // has file
        dir_close(d);
        return false;
      }
      dir_close(d);
    }
    dir_remove(dir, name);
    dir_close(dir);
  }
  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create_root())
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
