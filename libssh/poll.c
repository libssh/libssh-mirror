/*
 * poll.c - poll wrapper
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 *
 * vim: ts=2 sw=2 et cindent
 */

/* This code is based on glib's gpoll */

#include <errno.h>

#include "config.h"
#include "libssh/priv.h"

#ifdef HAVE_POLL
#include <poll.h>

int ssh_poll(pollfd_t *fds, nfds_t nfds, int timeout) {
  return poll((struct pollfd *) fds, nfds, timeout);
}

#else /* HAVE_POLL */
#ifdef _WIN32

#if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0600)

#include <winsock2.h>

int ssh_poll(pollfd_t *fds, nfds_t nfds, int timeout) {
  return WSAPoll(fds, nfds, timeout);
}

#else /* _WIN32_WINNT */

#ifndef STRICT
#define STRICT
#endif

#include <stdio.h>
#include <windows.h>

static int poll_rest (HANDLE *handles, int nhandles,
    pollfd_t *fds, nfds_t nfds, int timeout) {
  DWORD ready;
  pollfd_t *f;
  int recursed_result;

  if (nhandles == 0) {
    /* No handles to wait for, just the timeout */
    if (timeout == INFINITE) {
      ready = WAIT_FAILED;
    } else {
      SleepEx(timeout, 1);
      ready = WAIT_TIMEOUT;
    }
  } else {
    /* Wait for just handles */
    ready = WaitForMultipleObjectsEx(nhandles, handles, FALSE, timeout, TRUE);
#if 0
    if (ready == WAIT_FAILED)  {
      fprintf(stderr, "WaitForMultipleObjectsEx failed: %d\n", GetLastError());
    }
#endif
  }

  if (ready == WAIT_FAILED) {
    return -1;
  } else if (ready == WAIT_TIMEOUT || ready == WAIT_IO_COMPLETION) {
    return 0;
  } else if (ready >= WAIT_OBJECT_0 && ready < WAIT_OBJECT_0 + nhandles) {
    for (f = fds; f < &fds[nfds]; f++) {
      if ((HANDLE) f->fd == handles[ready - WAIT_OBJECT_0]) {
        f->revents = f->events;
      }
    }

    /*
     * If no timeout and polling several handles, recurse to poll
     * the rest of them.
     */
    if (timeout == 0 && nhandles > 1) {
      /* Remove the handle that fired */
      int i;
      if (ready < nhandles - 1) {
        for (i = ready - WAIT_OBJECT_0 + 1; i < nhandles; i++) {
          handles[i-1] = handles[i];
        }
      }
      nhandles--;
      recursed_result = poll_rest(handles, nhandles, fds, nfds, 0);
      if (recursed_result < 0) {
        return -1;
      }
      return recursed_result + 1;
    }
    return 1;
  }

  return 0;
}

int ssh_poll(pollfd_t *fds, nfds_t nfds, int timeout) {
  HANDLE handles[MAXIMUM_WAIT_OBJECTS];
  pollfd_t *f;
  int nhandles = 0;
  int rc = -1;

  if (fds == NULL) {
    errno = EFAULT;
    return -1;
  }

  if (nfds >= MAXIMUM_WAIT_OBJECTS) {
    errno = EINVAL;
    return -1;
  }

  for (f = fds; f < &fds[nfds]; f++) {
    if (f->fd > 0) {
      int i;

      /*
       * Don't add the same handle several times into the array, as
       * docs say that is not allowed, even if it actually does seem
       * to work.
       */
      for (i = 0; i < nhandles; i++) {
        if (handles[i] == (HANDLE) f->fd) {
          break;
        }
      }

      if (i == nhandles) {
        if (nhandles == MAXIMUM_WAIT_OBJECTS) {
          break;
        } else {
          handles[nhandles++] = (HANDLE) f->fd;
        }
      }
    }
  }

  if (timeout == -1) {
    timeout = INFINITE;
  }

  if (nhandles > 1) {
    /*
     * First check if one or several of them are immediately
     * available.
     */
    rc = poll_rest(handles, nhandles, fds, nfds, 0);

    /*
     * If not, and we have a significant timeout, poll again with
     * timeout then. Note that this will return indication for only
     * one event, or only for messages. We ignore timeouts less than
     * ten milliseconds as they are mostly pointless on Windows, the
     * MsgWaitForMultipleObjectsEx() call will timeout right away
     * anyway.
     */
    if (rc == 0 && (timeout == INFINITE || timeout >= 10)) {
      rc = poll_rest(handles, nhandles, fds, nfds, timeout);
    }
  } else {
    /*
     * Just polling for one thing, so no need to check first if
     * available immediately
     */
    rc = poll_rest(handles, nhandles, fds, nfds, timeout);
  }

  if (rc < 0) {
    for (f = fds; f < &fds[nfds]; f++) {
      f->revents = 0;
    }
    errno = EBADF;
  }

  return rc;
}

#endif /* _WIN32_WINNT */

#endif /* _WIN32 */

#endif /* HAVE_POLL */

