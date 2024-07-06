#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "devices/input.h"

struct semaphore file_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */
  int fd;struct file *file;
  switch (args[0]){
  case SYS_HALT: // 0
    shutdown_power_off();
    break;

  case SYS_EXIT: // 1
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit(args[1]);
    break;

  case SYS_EXEC: // 2
    f->eax = process_execute((const char*)args[1]);
    break;

  case SYS_WAIT: // 3
    f->eax = process_wait(args[1]);
    break;

  case SYS_CREATE: // 4
    sema_down(&file_lock);
    f->eax = filesys_create((char*)args[1], args[2]);
    sema_up(&file_lock);
    break;

  case SYS_REMOVE: // 5
    sema_down(&file_lock);
    f->eax = filesys_remove((char*)args[1]);
    sema_up(&file_lock);
    break;

  case SYS_OPEN: // 6
    sema_down(&file_lock);
    file = filesys_open((char*)args[1]);
    sema_up(&file_lock);
    if (file == NULL) {
      f->eax = -1;
      break;
    }
    fd = ++ thread_current()->pcb->fd_count; // Okay, I know it's shit
    struct fdtable *fdt = &thread_current()->pcb->fdt[fd];
    fdt->file_pointer = file;
    fdt->valid = true;
    f->eax = fd;
    break;

  case SYS_FILESIZE: // 7
    fd = args[1];
    file = get_file(thread_current()->pcb, fd);
    if (file == NULL) {
      f->eax = -1;
      break;
    }
    sema_down(&file_lock);
    f->eax = file_length(file);
    sema_up(&file_lock);
    break;

  case SYS_READ: // 8
    fd = args[1];
    if (fd == 0) {
      char* buffers = (void*)args[2];
      for (unsigned int i = 0; i < args[3]; i ++) {
        *(buffers ++) = input_getc();
      }
      f->eax = args[3];
      break;
    } else {
      file = get_file(thread_current()->pcb, fd);
      if (file == NULL) {
        f->eax = -1;
        break;
      }
      sema_down(&file_lock);
      f->eax = file_read(file, (void*)args[2], args[3]);
      sema_up(&file_lock);
      break;
    }

  case SYS_WRITE: // 9
    fd = args[1];
    if (fd == 1) {
      putbuf((void*)args[2], args[3]);
      f->eax = args[3];
      break;
    } else {
      file = get_file(thread_current()->pcb, fd);
      if (file == NULL) {
        f->eax = -1;
        break;
      }
      sema_down(&file_lock);
      f->eax = file_write(file, (void*)args[2], args[3]);
      sema_up(&file_lock);
      break;
    }

  case SYS_SEEK: // 10
    fd = args[1];
    file = get_file(thread_current()->pcb, fd);
    if (file == NULL) {
      f->eax = -1;
      break;
    }
    sema_down(&file_lock);
    file_seek(file, args[2]);
    sema_up(&file_lock);
    break;

  case SYS_TELL: // 11
    fd = args[1];
    file = get_file(thread_current()->pcb, fd);
    if (file == NULL) {
      f->eax = -1;
      break;
    }
    sema_down(&file_lock);
    f->eax = file_tell(file);
    sema_up(&file_lock);
    break;

  case SYS_CLOSE: // 12
    fd = args[1];
    file = get_file(thread_current()->pcb, fd);
    if (file == NULL)
      break;
    thread_current()->pcb->fdt[fd].valid = false;
    sema_down(&file_lock);
    file_close(file);
    sema_up(&file_lock);
    break;

  case SYS_PRACTICE: // who cares this number...
    f->eax = args[1] + 1;
    break;
  }
}
