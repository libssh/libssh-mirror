/*
 * connect.c - handles connections to ssh servers
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
/* getaddrinfo, freeaddrinfo, getnameinfo */
#define _WIN32_WINNT 0x0501

#include <winsock2.h>
#include <ws2tcpip.h>

#include "wspiapi.h" /* Workaround for w2k systems */

#else /* _WIN32 */

#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#endif /* _WIN32 */

#include "libssh/priv.h"

#ifndef HAVE_SELECT
#error "Your system must have select()"
#endif

#ifndef HAVE_GETADDRINFO
#error "Your system must have getaddrinfo()"
#endif

#ifdef _WIN32
static void sock_set_nonblocking(socket_t sock) {
  u_long nonblocking = 1;
  ioctlsocket(sock, FIONBIO, &nonblocking);
}

static void sock_set_blocking(socket_t sock) {
  u_long nonblocking = 0;
  ioctlsocket(sock, FIONBIO, &nonblocking);
}

#ifndef gai_strerror
char WSAAPI *gai_strerrorA(int code) {
  static char buf[256];

  snprintf(buf, sizeof(buf), "Undetermined error code (%d)", code);

  return buf;
}
#endif /* gai_strerror */

#else /* _WIN32 */
static void sock_set_nonblocking(socket_t sock) {
  fcntl(sock, F_SETFL, O_NONBLOCK);
}

static void sock_set_blocking(socket_t sock) {
  fcntl(sock, F_SETFL, 0);
}
#endif /* _WIN32 */

static int getai(const char *host, int port, struct addrinfo **ai) {
  const char *service = NULL;
  struct addrinfo hints;
  char s_port[10];

  ZERO_STRUCT(hints);

  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (port == 0) {
    hints.ai_flags = AI_PASSIVE;
  } else {
    snprintf(s_port, sizeof(s_port), "%hu", port);
    service = s_port;
  }

  return getaddrinfo(host, service, &hints, ai);
}

static int ssh_connect_ai_timeout(SSH_SESSION *session, const char *host,
    int port, struct addrinfo *ai, long timeout, long usec, socket_t s) {
  struct timeval to;
  fd_set set;
  int rc = 0;
  unsigned int len = sizeof(rc);

  enter_function();

  to.tv_sec = timeout;
  to.tv_usec = usec;

  sock_set_nonblocking(s);

  /* The return value is checked later */
  connect(s, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);

  FD_ZERO(&set);
  FD_SET(s, &set);

  rc = select(s + 1, NULL, &set, NULL, &to);
  if (rc == 0) {
    /* timeout */
    ssh_set_error(session, SSH_FATAL,
        "Timeout while connecting to %s:%d", host, port);
    close(s);
    leave_function();
    return -1;
  }

  if (rc < 0) {
    ssh_set_error(session, SSH_FATAL,
        "Select error: %s", strerror(errno));
    close(s);
    leave_function();
    return -1;
  }
  rc = 0;

  /* Get connect(2) return code. Zero means no error */
  getsockopt(s, SOL_SOCKET, SO_ERROR,(char *) &rc, &len);
  if (rc != 0) {
    ssh_set_error(session, SSH_FATAL,
        "Connect to %s:%d failed: %s", host, port, strerror(rc));
    close(s);
    leave_function();
    return -1;
  }

  /* s is connected ? */
  ssh_log(session, SSH_LOG_PACKET, "Socket connected with timeout\n");
  sock_set_blocking(s);

  leave_function();
  return s;
}

/**
 * @internal
 *
 * @brief Connect to an IPv4 or IPv6 host specified by its IP address or
 * hostname.
 *
 * @returns A file descriptor, < 0 on error.
 */
socket_t ssh_connect_host(SSH_SESSION *session, const char *host,
    const char *bind_addr, int port, long timeout, long usec) {
  socket_t s = -1;
  int rc;
  struct addrinfo *ai;
  struct addrinfo *itr;

  enter_function();

  rc = getai(host, port, &ai);
  if (rc != 0) {
    ssh_set_error(session, SSH_FATAL,
        "Failed to resolve hostname %s (%s)", host, gai_strerror(rc));
    leave_function();
    return -1;
  }

  for (itr = ai; itr != NULL; itr = itr->ai_next){
    /* create socket */
    s = socket(itr->ai_family, itr->ai_socktype, itr->ai_protocol);
    if (s < 0) {
      ssh_set_error(session, SSH_FATAL,
          "Socket create failed: %s", strerror(errno));
      continue;
    }

    if (bind_addr) {
      struct addrinfo *bind_ai;
      struct addrinfo *bind_itr;

      ssh_log(session, SSH_LOG_PACKET, "Resolving %s\n", bind_addr);

      rc = getai(host, 0, &bind_ai);
      if (rc != 0) {
        ssh_set_error(session, SSH_FATAL,
            "Failed to resolve bind address %s (%s)",
            bind_addr,
            gai_strerror(rc));
        leave_function();
        return -1;
      }

      for (bind_itr = bind_ai; bind_itr != NULL; bind_itr = bind_itr->ai_next) {
        if (bind(s, bind_itr->ai_addr, bind_itr->ai_addrlen) < 0) {
          ssh_set_error(session, SSH_FATAL,
              "Binding local address: %s", strerror(errno));
          continue;
        } else {
          break;
        }
      }
      freeaddrinfo(bind_ai);

      /* Cannot bind to any local addresses */
      if (bind_itr == NULL) {
        close(s);
        s = -1;
        continue;
      }
    }

    if (timeout || usec) {
      socket_t ret = ssh_connect_ai_timeout(session, host, port, itr,
          timeout, usec, s);
      leave_function();
      return ret;
    }

    if (connect(s, itr->ai_addr, itr->ai_addrlen) < 0) {
      ssh_set_error(session, SSH_FATAL, "Connect failed: %s", strerror(errno));
      close(s);
      s = -1;
      leave_function();
      continue;
    } else {
      /* We are connected */
      break;
    }
  }

  freeaddrinfo(ai);
  leave_function();

  return s;
}

/**
 * @addtogroup ssh_session
 * @{ */

/**
 * @brief A wrapper for the select syscall
 *
 * This functions acts more or less like the select(2) syscall.\n
 * There is no support for writing or exceptions.\n
 *
 * @param  channels     Arrays of channels pointers terminated by a NULL.
 *                      It is never rewritten.
 *
 * @param  outchannels  Arrays of same size that "channels", there is no need
 *                      to initialize it.
 *
 * @param  maxfd        Maximum +1 file descriptor from readfds.
 *
 * @param  readfds      A fd_set of file descriptors to be select'ed for
 *                      reading.
 *
 * @param  timeout      A timeout for the select.
 *
 * @return -1 if an error occured. E_INTR if it was interrupted. In that case,
 *          just restart it.
 *
 * @warning libssh is not threadsafe here. That means that if a signal is caught
 * during the processing of this function, you cannot call ssh functions on
 * sessions that are busy with ssh_select().
 *
 * @see select(2)
 */
int ssh_select(CHANNEL **channels, CHANNEL **outchannels, socket_t maxfd,
    fd_set *readfds, struct timeval *timeout) {
  struct timeval zerotime;
  fd_set localset, localset2;
  int rep;
  int set;
  int i;
  int j;

  zerotime.tv_sec = 0;
  zerotime.tv_usec = 0;

  /*
   * First, poll the maxfd file descriptors from the user with a zero-second
   * timeout. They have the bigger priority.
   */
  if (maxfd > 0) {
    memcpy(&localset, readfds, sizeof(fd_set));
    rep = select(maxfd, &localset, NULL, NULL, &zerotime);
    /* catch the eventual errors */
    if (rep==-1) {
      return -1;
    }
  }

  /* Poll every channel */
  j = 0;
  for (i = 0; channels[i]; i++) {
    if (channels[i]->session->alive) {
      if(channel_poll(channels[i], 0) > 0) {
        outchannels[j] = channels[i];
        j++;
      } else {
        if(channel_poll(channels[i], 1) > 0) {
          outchannels[j] = channels[i];
          j++;
        }
      }
    }
  }
  outchannels[j] = NULL;

  /* Look into the localset for active fd */
  set = 0;
  for (i = 0; (i < maxfd) && !set; i++) {
    if (FD_ISSET(i, &localset)) {
      set = 1;
    }
  }

  /* j != 0 means a channel has data */
  if( (j != 0) || (set != 0)) {
    if(maxfd > 0) {
      memcpy(readfds, &localset, sizeof(fd_set));
    }
    return 0;
  }

  /*
   * At this point, not any channel had any data ready for reading, nor any fd
   * had data for reading.
   */
  memcpy(&localset, readfds, sizeof(fd_set));
  for (i = 0; channels[i]; i++) {
    if (channels[i]->session->alive) {
      ssh_socket_fd_set(channels[i]->session->socket, &localset, &maxfd);
    }
  }

  rep = select(maxfd, &localset, NULL, NULL, timeout);
  if (rep == -1 && errno == EINTR) {
    /* Interrupted by a signal */
    return SSH_EINTR;
  }

  if (rep == -1) {
    /*
     * Was the error due to a libssh's channel or from a closed descriptor from
     * the user? User closed descriptors have been caught in the first select
     * and not closed since that moment. That case shouldn't occur at all
     */
    return -1;
  }

  /* Set the data_to_read flag on each session */
  for (i = 0; channels[i]; i++) {
    if (channels[i]->session->alive &&
        ssh_socket_fd_isset(channels[i]->session->socket,&localset)) {
      ssh_socket_set_toread(channels[i]->session->socket);
    }
  }

  /* Now, test each channel */
  j = 0;
  for (i = 0; channels[i]; i++) {
    if (channels[i]->session->alive &&
        ssh_socket_fd_isset(channels[i]->session->socket,&localset)) {
      if ((channel_poll(channels[i],0) > 0) ||
          (channel_poll(channels[i], 1) > 0)) {
        outchannels[j] = channels[i];
        j++;
      }
    }
  }
  outchannels[j] = NULL;

  FD_ZERO(&localset2);
  for (i = 0; i < maxfd; i++) {
    if (FD_ISSET(i, readfds) && FD_ISSET(i, &localset)) {
      FD_SET(i, &localset2);
    }
  }

  memcpy(readfds, &localset2, sizeof(fd_set));

  return 0;
}

/** @} */
