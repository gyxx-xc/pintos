#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp);

// this pcb init is for main thread only.
/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  sema_init(&file_lock, 1);

  if (success) {
    lock_init(&t->pcb->pcb_lock);
    list_init(&t->pcb->children);
  }
  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;

  struct thread* t = thread_current();
  sema_init(&t->pcb->child_load, 0);

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  void** list = malloc(2 * sizeof(void*));
  *list = fn_copy;
  *(list + 1) = t;

  lock_acquire(&t->pcb->pcb_lock);
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, list);
  sema_down(&t->pcb->child_load);
  if (tid == TID_ERROR) {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  if (!t->pcb->load_success) {
    return TID_ERROR;
  }
  lock_release(&t->pcb->pcb_lock);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* list) {
  char* file_name = (char*)*(void**)list;
  struct thread* parent = *((void**)list + 1);
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;
  int file_name_len = strlen(file_name);
  int argc_ = 0;

  // very simple automechine
  // get the argc
  bool prev = false;
  for (int i = 0; i < file_name_len; i++) {
    if (file_name[i] == ' ') {
      file_name[i] = '\0';
      prev = false;
    } else {
      if (!prev)
        argc_++;
      prev = true;
    }
  }

  /* Allocate process control block */
  struct process* pcb = malloc(sizeof(struct process));
  success = pcb_success = pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // STUB: I think I assume pcb is all 0 somewhere
    memset(pcb, 0, sizeof(struct process));

    // Ensure that timer_interrunew_pcbpt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    pcb->pagedir = NULL;
    t->pcb = pcb;

    // Continue initializing the PCB as normal
    pcb->main_thread = t;
    strlcpy(pcb->process_name, file_name, sizeof pcb->process_name);
    pcb->pid = t->tid;

    pcb->parent = parent->pcb;
    list_init(&pcb->children);
    pcb->self_list_elem.process = pcb;
    list_push_back(&parent->pcb->children, &pcb->self_list_elem.elem);

    list_init(&pcb->pthreads);
    lock_init(&pcb->pcb_lock);
    sema_init(&pcb->exited, 0);

    pcb->fd_count = 1;
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    success = load(file_name, &if_.eip, &if_.esp);
  }

  /* setup function call stack (args) for main */
  if (success) {
    /*
                                          00 00 00 00 |            ....|
      04 00 00 00 d8 ff ff bf-ed ff ff bf f5 ff ff bf |................|
      f8 ff ff bf fc ff ff bf-00 00 00 00 00 2f 62 69 |............./bi|
      6e 2f 6c 73 00 2d 6c 00-66 6f 6f 00 62 61 72 00 |n/ls.-l.foo.bar.|
    */
    if_.esp -= file_name_len + 1;
    char* file_name_data = if_.esp;
    memcpy(if_.esp, file_name, file_name_len + 1);
    // stack align
    while ((int)(if_.esp - (argc_ + 3) * 4) & 15)
      *(char*)(--if_.esp) = 0;
    // argv[argc] = 0
    if_.esp -= 4;
    *(char**)if_.esp = 0;

    // argv
    if_.esp -= 4 * argc_;
    prev = false;
    for (int i = 0; i < file_name_len; i++) {
      if (file_name_data[i] != '\0') {
        if (!prev) {
          *(char**)if_.esp = file_name_data + i;
          if_.esp += 4;
        }
        prev = true;
      } else {
        prev = false;
      }
    }
    if_.esp -= 4 * argc_;
    // argv*
    if_.esp -= 4;
    *(char***)if_.esp = if_.esp + 4;

    // argc
    if_.esp -= 4;
    *(int*)if_.esp = argc_;
    // fake return address
    if_.esp -= 4;
    *(int*)if_.esp = 0;
  }

  /* fpu init (load from thread) */
  if (success) {
    // since the fpu is init from the thread already
    asm("fsave (%0)" ::"g"(&if_.fpu));
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    list_pop_back(&parent->pcb->children);
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  if (!success) {
    parent->pcb->load_success = false;
    sema_up(&parent->pcb->child_load);
    thread_exit();
  }

  parent->pcb->load_success = true;
  sema_up(&parent->pcb->child_load);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

// free the pcb here
/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  struct list* c = &thread_current()->pcb->children;
  lock_acquire(&thread_current()->pcb->pcb_lock);
  if (list_empty(c))
    return -1;
  for (struct list_elem* e = list_begin(c); e != NULL; e = list_next(e)) {
    struct child_list_elem* c_elem = list_entry(e, struct child_list_elem, elem);
    if (get_pid(c_elem->process) == child_pid) {
      list_remove(e);
      // TODO: review needed
      // cause the child is done now,
      // so, page_dir is not a problem, I think
      lock_release(&thread_current()->pcb->pcb_lock);
      sema_down(&c_elem->process->exited);
      int status = c_elem->process->exit_status;
      free(c_elem->process);
      return status;
    }
  }
  lock_release(&thread_current()->pcb->pcb_lock);
  return -1;
}

/* Free the current process's resources. */
void process_exit(int exit_status) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  // FIXME: add pcb_lock sync here
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
       cur->pcb->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  // free all the child pcb notx waited yet
  struct list* c = &cur->pcb->children;
  if (!list_empty(c)) {
    for (struct list_elem* e = list_begin(c); e != NULL; e = list_remove(e)) {
      struct child_list_elem* c_elem = list_entry(e, struct child_list_elem, elem);
      if (sema_try_down(&c_elem->process->exited)) {
        free(c_elem->process);
      } else {
        c_elem->process->parent = NULL;
      }
      free(e);
    }
  }

  // free all fdt not free yet
  for (int i = 1; i <= cur->pcb->fd_count; i++) {
    struct file* file = get_file(cur->pcb, i);
    if (file != NULL) {
      cur->pcb->fdt[i].valid = false;
      file_close(file);
    }
  }

  //free all sync pointer
  for (int i = 0; i < cur->pcb->sy_count; i ++) {
    // TEMP: maybe release the lock here?
    free(cur->pcb->sync_p[i]);
  }

  file_close(cur->pcb->file); // close & unlock self

  sema_up(&cur->pcb->exited);
  cur->pcb->exit_status = exit_status;

  // this orphan pcb should be freed by the inherited parent originally.
  // however, there's no inherit in pintos, so we free it here
  // it is ugly, I know...
  if (cur->pcb->parent == NULL) {
    /* Free the PCB of this process and kill this thread
       Avoid race where PCB is freed before t->pcb is set to NULL
       If this happens, then an unfortuantely timed timer interrupt
       can try to activate the pagedir, but it is now freed memory */
    struct process* pcb_to_free = cur->pcb;
    cur->pcb = NULL;
    free(pcb_to_free);
  }

  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  // lock the file
  file_deny_write(file);
  t->pcb->file = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
             Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
             Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->pid; }

/* Gets the file of a process by the given fd */
struct file* get_file(struct process* pcb, int fd) {
  if (fd == 0 || fd == 1)
    return NULL;
  if (fd > pcb->fd_count)
    return NULL;
  struct fdtable* fdt = &pcb->fdt[fd];
  if (!fdt->valid)
    return NULL;
  return fdt->file_pointer;
}

void* get_sync(struct process* pcb, int sync, bool type) {
    if (sync >= pcb->sy_count) {
      return NULL;
    }
    if (pcb->sync_type[sync] != type) {
      return NULL;
    }
    return pcb->sync_p[sync];
}

static struct pthread_list_elem*
get_thread_elem_from_tid (struct process* pcb, tid_t tid) {
  struct list* list = &pcb->pthreads;
  struct list_elem* e;
  for (e = list_begin(list);
       e != list_end(list);
       e = list_next(e))
    if (list_entry(e, struct pthread_list_elem, elem)->tid == tid)
      return list_entry(e, struct pthread_list_elem, elem);
  return NULL;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) {
  tid_t tid;
  struct semaphore child_l;
  sema_init(&child_l, 0);
  void* exec_[5] = {sf, tf, arg, thread_current()->pcb, &child_l};
  /* lock_acquire(&thread_current()->pcb->pcb_lock); */
  tid = thread_create("pthread_execute", thread_get_priority(),
                      start_pthread, exec_);
  //wait until it load
  sema_down(&child_l);
  if (tid == TID_ERROR) return TID_ERROR;

  // check if the thread is load success (in pthread list)
  if (get_thread_elem_from_tid(thread_current()->pcb, tid) != NULL)
    return tid;
  /* lock_release(&thread_current()->pcb->pcb_lock); */
  // not found
  return TID_ERROR;
}

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
static bool setup_thread_stack(void** esp) {
  process_activate();
  uint8_t* kpage;
  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage == NULL) return false;

  // TEMP: I suppose most have 128 thread here
  for (int i = 2; i < 128; i ++) {
    // find the first not alloc stack page
    if (install_page(((uint8_t*)PHYS_BASE) - PGSIZE*i,
                     kpage, true)){
      *esp = PHYS_BASE - PGSIZE*(i-1);
      return true;
    }
  }

  // fail to find a unused page
  palloc_free_page(kpage);
  return false;
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec) {
  // exec = 0:sf, 1:tf, 2:arg, 3:pcb, 4:child_load
  void** exec_ = (void**)exec;
  struct process* pcb = exec_[3];
  struct thread* t = thread_current();
  struct intr_frame if_;
  struct pthread_list_elem* p_elem;
  int success, p_success;

  t->pcb = pcb;
  p_elem = malloc(sizeof(struct pthread_list_elem));
  success = p_success = p_elem != NULL;

  if (success) {
    p_elem->tid = thread_tid();
    sema_init(&p_elem->exited, 0);
    p_elem->thread = t;
    list_push_back(&pcb->pthreads, &p_elem->elem);
  }

  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = setup_thread_stack(&if_.esp);
  }

  /* setup function call stack (args) for sf */
  if (success) {
    p_elem->stack_base = if_.esp - PGSIZE;
    // arg
    if_.esp -= 4;
    *(void**)if_.esp = exec_[2];
    // tf
    if_.esp -= 4;
    *(void**)if_.esp = exec_[1];
    // fake ret
    if_.esp -= 4;
    *(int*)if_.esp = 0;

    if_.eip = exec_[0];
  }

  /* Clean up. Exit on failure or jump to userspace */
  if (!success && p_success) {
    list_pop_back(&pcb->pthreads);
    free(p_elem);
  }
  if (!success) {
    sema_up(exec_[4]);
    thread_exit();
  }
  sema_up(exec_[4]);
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid) {
  lock_acquire(&thread_current()->pcb->pcb_lock);
  struct pthread_list_elem* elem =
      get_thread_elem_from_tid(thread_current()->pcb, tid);
  if (elem == NULL) {
    lock_release(&thread_current()->pcb->pcb_lock);
    return TID_ERROR;
  }
  lock_release(&thread_current()->pcb->pcb_lock);

  sema_down(&elem->exited);
  list_remove(&elem->elem);
  free(elem);
  return tid;
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  lock_acquire(&thread_current()->pcb->pcb_lock);
  struct pthread_list_elem* elem =
    get_thread_elem_from_tid(thread_current()->pcb, thread_tid());
  if (elem == NULL) {
    lock_release(&thread_current()->pcb->pcb_lock);
    thread_exit(); // I think we can do nothing if it's NULL
  }

  uint8_t* kpage =
    pagedir_get_page(thread_current()->pcb->pagedir, elem->stack_base);
  pagedir_clear_page(thread_current()->pcb->pagedir, elem->stack_base);
  palloc_free_page(kpage);

  sema_up(&elem->exited);
  lock_release(&thread_current()->pcb->pcb_lock);
  thread_exit();
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {}
