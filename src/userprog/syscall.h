#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

extern struct semaphore file_lock;

void syscall_init(void);

#endif /* userprog/syscall.h */
