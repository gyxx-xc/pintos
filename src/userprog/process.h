#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "lib/kernel/list.h"
#include <stdint.h>
// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

struct child_list_elem {
  struct process* process;
  struct list_elem elem;
};

struct fdtable {
  bool valid;
  struct file* file_pointer;
};

// we need this is because the thread can be freed before join
// so we need to save these information in list.
struct pthread_list_elem {
  tid_t tid;
  void* stack_base;
  struct semaphore exited;
  struct thread* thread;
  struct list_elem elem;
};

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */

  /* mine */
  pid_t pid;
  struct file* file;
  // a lock so that only one thread is modifing pcb
  // seems not very elegant?
  struct lock pcb_lock;

  struct fdtable fdt[128];
  int fd_count;

  // this is because thread might be
  // freed before process
  // only one child is load one time
  // so only need one bool?
  struct semaphore child_load;
  bool load_success;
  struct semaphore exited;
  int exit_status;

  struct process* parent;
  struct list children;
  struct child_list_elem self_list_elem;

  struct list pthreads;
  void* sync_p[128]; //sync(sema/lock) pointer
  bool sync_type[128]; //true for lock, false for sema
  uint8_t sy_count;
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(int exit_status);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);
struct file* get_file(struct process* pcb, int fd);
void* get_sync(struct process* pcb, int sync, bool type);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
