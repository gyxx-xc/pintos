#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  //printf("System call number: %d\n", args[0]);

  if (args[0] == SYS_OPEN) {
    struct file* file = filesys_open((char*)args[1]);
    struct process* pcb = thread_current()->pcb;
    pcb->fdt[pcb->fdt_count ++].file_pointer = file;
    f->eax = 0;
  }

  if (args[0] == SYS_CLOSE) {

  }

  if (args[0] == SYS_WRITE) {
    int fd = args[1];
    struct process* pcb = thread_current()->pcb;
    if (fd < 0 || fd >= pcb->fdt_count) {
      f->eax = -1;
      return;
    } else if (fd == 1) {
      putbuf((void*)args[2], args[3]);
    } else {
      struct fdtable fdt = thread_current()->pcb->fdt[fd];
      if (!fdt.valid) {
        f->eax = -1;
        return;
      }
      file_deny_write(fdt.file_pointer);
      file_write(fdt.file_pointer, (char*)args[2], 0);
      file_allow_write(fdt.file_pointer);
    }
  }

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  }
}
