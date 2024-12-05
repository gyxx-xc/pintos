#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "lib/float.h"

struct semaphore file_lock;

static void syscall_handler(struct intr_frame*);

static bool put_user(uint8_t*, uint8_t);
static int get_user(const uint8_t*);

static bool check_user_string(const char*);
static bool check_user_buff(const uint8_t*, off_t);
static void put_user_buff(const uint8_t*, uint8_t*, off_t);

static bool check_user32(const uint32_t*);
static bool check_args(uint32_t*, int);

static void kill_process(void);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  if (!check_user32(args))
    kill_process();

  printf("System call number: %d\n", args[0]);
  int fd;
  struct file* file;
  switch (args[0]) {
  case SYS_HALT: // 0
    shutdown_power_off();
    return;

  case SYS_EXIT: // 1
    check_args(args, 1);
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit(args[1]);
    return;

  case SYS_EXEC: // 2
    check_args(args, 1);
    check_user_string((void*)args[1]);
    f->eax = process_execute((const char*)args[1]);
    return;

  case SYS_WAIT: // 3
    check_args(args, 1);
    f->eax = process_wait(args[1]);
    return;

  case SYS_CREATE: // 4
    check_args(args, 1);
    check_user_string((void*)args[1]);
    sema_down(&file_lock);
    f->eax = filesys_create((char*)args[1], args[2]);
    sema_up(&file_lock);
    return;

  case SYS_REMOVE: // 5
    check_args(args, 1);
    check_user_string((void*)args[1]);
    sema_down(&file_lock);
    f->eax = filesys_remove((char*)args[1]);
    sema_up(&file_lock);
    return;

  case SYS_OPEN: // 6
    check_args(args, 1);
    check_user_string((void*)args[1]);
    sema_down(&file_lock);
    file = filesys_open((char*)args[1]);
    sema_up(&file_lock);
    if (file == NULL) {
      f->eax = -1;
      return;
    }
    fd = ++thread_current()->pcb->fd_count; // Okay, I know it's shit
    struct fdtable* fdt = &thread_current()->pcb->fdt[fd];
    fdt->file_pointer = file;
    fdt->valid = true;
    f->eax = fd;
    return;

  case SYS_FILESIZE: // 7
    check_args(args, 1);
    fd = args[1];
    file = get_file(thread_current()->pcb, fd);
    if (file == NULL) {
      f->eax = -1;
      return;
    }
    sema_down(&file_lock);
    f->eax = file_length(file);
    sema_up(&file_lock);
    return;

  case SYS_READ: // 8
    check_args(args, 3);
    fd = args[1];
    uint8_t* buffer = malloc(sizeof(uint8_t) * args[3]);
    if (fd == 0) {
      for (unsigned int i = 0; i < args[3]; i++) {
        *(buffer++) = input_getc();
      }
      f->eax = args[3];
    } else {
      file = get_file(thread_current()->pcb, fd);
      if (file == NULL) {
        f->eax = -1;
        return;
      }
      sema_down(&file_lock);
      f->eax = file_read(file, buffer, args[3]);
      sema_up(&file_lock);
    }
    put_user_buff(buffer, (uint8_t*)args[2], f->eax);
    return;

  case SYS_WRITE: // 9
    check_args(args, 3);
    fd = args[1];
    check_user_buff((void*)args[2], args[3]);
    if (fd == 1) {
      putbuf((void*)args[2], args[3]);
      f->eax = args[3];
      return;
    } else {
      file = get_file(thread_current()->pcb, fd);
      if (file == NULL) {
        f->eax = -1;
        return;
      }
      sema_down(&file_lock);
      f->eax = file_write(file, (void*)args[2], args[3]);
      sema_up(&file_lock);
      return;
    }

  case SYS_SEEK: // 10
    check_args(args, 2);
    fd = args[1];
    file = get_file(thread_current()->pcb, fd);
    if (file == NULL) {
      f->eax = -1;
      return;
    }
    sema_down(&file_lock);
    file_seek(file, args[2]);
    sema_up(&file_lock);
    return;

  case SYS_TELL: // 11
    check_args(args, 1);
    fd = args[1];
    file = get_file(thread_current()->pcb, fd);
    if (file == NULL) {
      f->eax = -1;
      return;
    }
    sema_down(&file_lock);
    f->eax = file_tell(file);
    sema_up(&file_lock);
    return;

  case SYS_CLOSE: // 12
    check_args(args, 1);
    fd = args[1];
    file = get_file(thread_current()->pcb, fd);
    if (file == NULL)
      return;
    thread_current()->pcb->fdt[fd].valid = false;
    sema_down(&file_lock);
    file_close(file);
    sema_up(&file_lock);
    return;

  case SYS_PT_CREATE: // 15
    thread_create("t", thread_get_priority(),
                  (pthread_fun)args[1],
                  &args[2]);
    return;

  case SYS_PT_EXIT: // 16
    return;

  case SYS_PT_JOIN: // 17
    return;

  case SYS_LOCK_INIT:
    f->eax = lock_init((void*)args[1]);
    return;

  case SYS_LOCK_ACQUIRE:
    return;

  case SYS_LOCK_RELEASE:
    return;

  case SYS_SEMA_INIT:
    return;

  case SYS_SEMA_DOWN:
    return;

  case SYS_SEMA_UP:
    return;

  case SYS_GET_TID:
    return;


  case SYS_PRACTICE: // who cares this number...
    check_args(args, 1);
    f->eax = args[1] + 1;
    return;

  case SYS_COMPUTE_E: // and also this one
    check_args(args, 1);
    f->eax = sys_sum_to_e(args[1]);
    return;
  }

  // other case including:
  // args not found
  kill_process();
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful,
   -1 if a segfault occurred. */
static int get_user(const uint8_t* uaddr) {
  if ((void*)uaddr >= PHYS_BASE)
    return -1;
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful,
   false if a segfault occurred. */
static bool put_user(uint8_t* udst, uint8_t byte) {
  if ((void*)udst >= PHYS_BASE)
    return false;
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:" : "=&a"(error_code), "=m"(*udst) : "q"(byte));
  return error_code != -1;
}

static bool check_user_string(const char* input) {
  int i = 0;
  while (true) {
    i = get_user((void*)input++);
    if (i == -1)
      kill_process();
    if ((char)i == '\0')
      return true;
  }
}

static bool check_user_buff(const uint8_t* input, off_t size) {
  for (int i = 0; i < size; i++)
    if (get_user(input++) == -1)
      kill_process();
  return true;
}

static void put_user_buff(const uint8_t* output, uint8_t* buff, off_t size) {
  for (int i = 0; i < size; i++)
    if (!put_user(buff++, *(output++)))
      kill_process();
}

static bool check_user32(const uint32_t* uaddr) {
  return (get_user((uint8_t*)uaddr) != -1) && (get_user((uint8_t*)uaddr + 1) != -1) &&
    (get_user((uint8_t*)uaddr + 2) != -1) && (get_user((uint8_t*)uaddr + 3) != -1);
}

static bool check_args(uint32_t* args, int argc) {
  for (int i = 0; i < argc; i++) {
    // four if for a 32bit args
    if (!check_user32((void*)(++args)))
      kill_process();
  }
  return true;
}

static void kill_process(void) {
  printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
  process_exit(-1);
  NOT_REACHED();
}
