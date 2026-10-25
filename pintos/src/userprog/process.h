#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <list.h>
#include <stdbool.h>
#include "threads/synch.h"
#include "threads/thread.h"

struct file;

/* Open file table entry owned by a user process. */
struct fd_entry
  {
    int fd;                  /* File descriptor number (>= 2). */
    struct file *file;       /* Open file. */
    struct list_elem elem;   /* Element in the owner's open_files. */
  };

/* Shared status record between a parent process and one child process. */
struct child_status
  {
    tid_t tid;                  /* Child's thread/process id. */
    bool has_been_waited;       /* True once the parent has waited. */
    struct semaphore sema_load; /* Child ups after load(); parent downs. */
    bool load_success;          /* Result of load(), set before sema_load up. */
    struct semaphore sema_exit; /* Child ups at exit; parent downs in wait. */
    int exit_status;            /* Child's exit code, set before sema_exit up. */
    int ref_count;              /* Parent + child references (starts at 2). */
    struct lock lock_ref;       /* Protects ref_count. */
    struct list_elem elem;      /* Element in the parent's children list. */
  };

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
