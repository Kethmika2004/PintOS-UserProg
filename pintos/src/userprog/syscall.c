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
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

/* Forward declarations. */
static void syscall_handler (struct intr_frame *);
static void fail_invalid_access (void) NO_RETURN;
static bool is_valid_ptr (const void *uaddr);
static void check_valid_buffer (const void *uaddr, size_t size);
static void check_valid_string (const char *ustr) UNUSED;
static uint32_t get_user_arg (const void *uaddr);
static uint32_t get_arg (struct intr_frame *f, int n);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Memory Validation Helpers. */

/* Terminates the thread if it attempts an illegal memory access. */
static void
fail_invalid_access (void)
{
  thread_current ()->exit_code = -1;
  thread_exit ();
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
      thread_current ()->exit_code = (int) get_arg (f, 1);
      thread_exit ();
      break;

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
            f->eax = (uint32_t) -1;
          }
        break;
      }

    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_CREATE:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_READ:
    case SYS_SEEK:
    case SYS_TELL:
    case SYS_CLOSE:
    default:
      thread_current ()->exit_code = -1;
      thread_exit ();
      break;
    }
}