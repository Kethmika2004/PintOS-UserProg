#ifndef USERPROG
#define USERPROG
#endif

#include "userprog/syscall.h"
#include <debug.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

/* Global lock serializing access to the file system. */
struct lock filesys_lock;

/* Forward declarations. */
static void syscall_handler (struct intr_frame *);
static void exit_with_status (int status) NO_RETURN;
static void fail_invalid_access (void) NO_RETURN;
static bool is_valid_ptr (const void *uaddr);
static void check_valid_buffer (const void *uaddr, size_t size);
static void check_valid_string (const char *ustr);
static uint32_t get_user_arg (const void *uaddr);
static uint32_t get_arg (struct intr_frame *f, int n);
static struct fd_entry *find_fd (int fd);

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Terminates the current user process with the given exit status. */
static void
exit_with_status (int status)
{
  thread_current ()->exit_code = status;
  thread_exit ();
}

/* Memory Validation Helpers. */

/* Terminates the thread if it attempts an illegal memory access. */
static void
fail_invalid_access (void)
{
  exit_with_status (-1);
}

/* Checks if a pointer is in user space and mapped in the page table. */
static bool
is_valid_ptr (const void *uaddr)
{
  return (uaddr != NULL
          && is_user_vaddr (uaddr)
          && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}

/* Validates that a user memory buffer [uaddr, uaddr + size) is safe to access. */
static void
check_valid_buffer (const void *uaddr, size_t size)
{
  uintptr_t cur_page;
  uintptr_t last_page;

  if (size == 0)
    return;

  if (uaddr == NULL)
    fail_invalid_access ();

  /* Guard against 32-bit arithmetic overflow. */
  if ((uintptr_t) uaddr + size < (uintptr_t) uaddr)
    fail_invalid_access ();

  /* Both ends of the buffer must be strictly below PHYS_BASE. */
  if (!is_user_vaddr (uaddr)
      || !is_user_vaddr ((const uint8_t *) uaddr + size - 1))
    fail_invalid_access ();

  /* Verify every distinct virtual page the buffer touches. */
  cur_page = (uintptr_t) pg_round_down (uaddr);
  last_page = (uintptr_t) pg_round_down ((const uint8_t *) uaddr + size - 1);

  while (cur_page <= last_page)
    {
      if (pagedir_get_page (thread_current ()->pagedir,
                            (const void *) cur_page) == NULL)
        fail_invalid_access ();

      cur_page += PGSIZE;
    }
}

/* Validates a null-terminated string byte-by-byte until reaching '\0'. */
static void
check_valid_string (const char *ustr)
{
  const char *ptr;

  if (ustr == NULL)
    fail_invalid_access ();

  ptr = ustr;
  while (true)
    {
      /* Check validity at the start and whenever crossing a page boundary. */
      if ((uintptr_t) ptr % PGSIZE == 0 || ptr == ustr)
        {
          if (!is_valid_ptr (ptr))
            fail_invalid_access ();
        }

      if (*ptr == '\0')
        break;

      ptr++;
    }
}

/* Reads a 4-byte value from the user stack safely. */
static uint32_t
get_user_arg (const void *uaddr)
{
  check_valid_buffer (uaddr, sizeof (uint32_t));
  return *(const uint32_t *) uaddr;
}

/* Reads the Nth 4-byte argument slot relative to the user stack pointer. */
static uint32_t
get_arg (struct intr_frame *f, int n)
{
  return get_user_arg ((uint8_t *) f->esp + 4 * n);
}

/* Looks up FD in the current thread's open file table, returning NULL
   if no matching descriptor is open. */
static struct fd_entry *
find_fd (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->open_files); e != list_end (&cur->open_files);
       e = list_next (e))
    {
      struct fd_entry *fde = list_entry (e, struct fd_entry, elem);
      if (fde->fd == fd)
        return fde;
    }
  return NULL;
}

/* System Call Dispatcher. */

static void
syscall_handler (struct intr_frame *f) 
{
  /* Validate that the stack pointer itself is safe to read the syscall number. */
  int syscall_num = (int) get_user_arg (f->esp);

  switch (syscall_num)
    {
    case SYS_HALT:
      shutdown_power_off ();
      break;

    case SYS_EXIT:
      exit_with_status ((int) get_arg (f, 1));
      break;

    case SYS_EXEC:
      {
        const char *cmd_line = (const char *) get_arg (f, 1);
        check_valid_string (cmd_line);
        f->eax = (uint32_t) process_execute (cmd_line);
        break;
      }

    case SYS_WAIT:
      f->eax = (uint32_t) process_wait ((tid_t) get_arg (f, 1));
      break;

    case SYS_CREATE:
      {
        const char *file = (const char *) get_arg (f, 1);
        unsigned initial_size = (unsigned) get_arg (f, 2);

        check_valid_string (file);
        lock_acquire (&filesys_lock);
        f->eax = filesys_create (file, initial_size);
        lock_release (&filesys_lock);
        break;
      }

    case SYS_REMOVE:
      {
        const char *file = (const char *) get_arg (f, 1);

        check_valid_string (file);
        lock_acquire (&filesys_lock);
        f->eax = filesys_remove (file);
        lock_release (&filesys_lock);
        break;
      }

    case SYS_OPEN:
      {
        const char *file = (const char *) get_arg (f, 1);
        struct file *fp;
        struct fd_entry *fde;

        check_valid_string (file);
        lock_acquire (&filesys_lock);
        fp = filesys_open (file);
        lock_release (&filesys_lock);

        if (fp == NULL)
          {
            f->eax = (uint32_t) -1;
            break;
          }

        fde = malloc (sizeof *fde);
        if (fde == NULL)
          {
            lock_acquire (&filesys_lock);
            file_close (fp);
            lock_release (&filesys_lock);
            f->eax = (uint32_t) -1;
            break;
          }

        fde->fd = thread_current ()->next_fd++;
        fde->file = fp;
        list_push_back (&thread_current ()->open_files, &fde->elem);
        f->eax = (uint32_t) fde->fd;
        break;
      }

    case SYS_FILESIZE:
      {
        int fd = (int) get_arg (f, 1);
        struct fd_entry *fde = find_fd (fd);

        if (fde == NULL)
          exit_with_status (-1);

        lock_acquire (&filesys_lock);
        f->eax = (uint32_t) file_length (fde->file);
        lock_release (&filesys_lock);
        break;
      }

    case SYS_READ:
      {
        int fd = (int) get_arg (f, 1);
        uint8_t *buffer = (uint8_t *) get_arg (f, 2);
        unsigned size = (unsigned) get_arg (f, 3);

        check_valid_buffer (buffer, size);

        if (fd == 0)
          {
            unsigned i;
            for (i = 0; i < size; i++)
              buffer[i] = input_getc ();
            f->eax = size;
          }
        else
          {
            struct fd_entry *fde = find_fd (fd);
            if (fde == NULL)
              exit_with_status (-1);

            lock_acquire (&filesys_lock);
            f->eax = (uint32_t) file_read (fde->file, buffer, size);
            lock_release (&filesys_lock);
          }
        break;
      }

    case SYS_WRITE:
      {
        int fd = (int) get_arg (f, 1);
        const char *buffer = (const char *) get_arg (f, 2);
        unsigned size = (unsigned) get_arg (f, 3);

        check_valid_buffer (buffer, size);

        if (fd == 1)
          {
            size_t offset = 0;
            while (offset < size)
              {
                size_t chunk = size - offset > 256 ? 256 : size - offset;
                putbuf (buffer + offset, chunk);
                offset += chunk;
              }
            f->eax = size;
          }
        else
          {
            struct fd_entry *fde = find_fd (fd);
            if (fde == NULL)
              exit_with_status (-1);

            lock_acquire (&filesys_lock);
            f->eax = (uint32_t) file_write (fde->file, buffer, size);
            lock_release (&filesys_lock);
          }
        break;
      }

    case SYS_SEEK:
      {
        int fd = (int) get_arg (f, 1);
        unsigned position = (unsigned) get_arg (f, 2);
        struct fd_entry *fde = find_fd (fd);

        if (fde == NULL)
          exit_with_status (-1);

        lock_acquire (&filesys_lock);
        file_seek (fde->file, position);
        lock_release (&filesys_lock);
        break;
      }

    case SYS_TELL:
      {
        int fd = (int) get_arg (f, 1);
        struct fd_entry *fde = find_fd (fd);

        if (fde == NULL)
          exit_with_status (-1);

        lock_acquire (&filesys_lock);
        f->eax = (uint32_t) file_tell (fde->file);
        lock_release (&filesys_lock);
        break;
      }

    case SYS_CLOSE:
      {
        int fd = (int) get_arg (f, 1);
        struct fd_entry *fde = find_fd (fd);

        if (fde == NULL)
          exit_with_status (-1);

        list_remove (&fde->elem);
        lock_acquire (&filesys_lock);
        file_close (fde->file);
        lock_release (&filesys_lock);
        free (fde);
        break;
      }

    default:
      exit_with_status (-1);
      break;
    }
}