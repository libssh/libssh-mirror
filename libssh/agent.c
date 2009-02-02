/*
 * agent.c - ssh agent functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008-2009 by Andreas Schneider <mail@cynapses.org>
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
 */

/* This file is based on authfd.c from OpenSSH */

#ifndef _WIN32

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <poll.h>
#include <unistd.h>

#include "libssh/agent.h"
#include "libssh/priv.h"

/* macro to check for "agent failure" message */
#define agent_failed(x) \
  (((x) == SSH_AGENT_FAILURE) || ((x) == SSH_COM_AGENT2_FAILURE) || \
   ((x) == SSH2_AGENT_FAILURE))

static u32 agent_get_u32(const void *vp) {
  const u8 *p = (const u8 *)vp;
  u32 v;

  v  = (u32)p[0] << 24;
  v |= (u32)p[1] << 16;
  v |= (u32)p[2] << 8;
  v |= (u32)p[3];

  return (v);
}

static void agent_put_u32(void *vp, u32 v) {
  u8 *p = (u8 *)vp;

  p[0] = (u8)(v >> 24) & 0xff;
  p[1] = (u8)(v >> 16) & 0xff;
  p[2] = (u8)(v >> 8) & 0xff;
  p[3] = (u8)v & 0xff;
}

static size_t atomicio(struct socket *s, void *buf, size_t n, int do_read) {
  char *b = buf;
  size_t pos = 0;
  ssize_t res;
  struct pollfd pfd;
  int fd = ssh_socket_get_fd(s);

  pfd.fd = fd;
  pfd.events = do_read ? POLLIN : POLLOUT;

  while (n > pos) {
    if (do_read) {
      res = read(fd, b + pos, n - pos);
    } else {
      res = write(fd, b + pos, n - pos);
    }
    switch (res) {
      case -1:
        /* TODO: set error */
        if (errno == EINTR) {
          continue;
        }
#ifdef EWOULDBLOCK
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
#else
        if (errno == EAGAIN) {
#endif
          (void) poll(&pfd, 1, -1);
          continue;
        }
        return 0;
    case 0:
      errno = EPIPE;
      return pos;
    default:
      pos += (size_t) res;
    }
  }

  return pos;
}

AGENT *agent_new(struct ssh_session *session) {
  AGENT *agent = NULL;

  agent = malloc(sizeof(*agent));
  if (agent) {
    agent->count = 0;
    agent->sock = ssh_socket_new(session);
  }

  return agent;
}

void agent_close(struct agent_struct *agent) {
  if (getenv("SSH_AUTH_SOCK")) {
    ssh_socket_close(agent->sock);
  }
}

void agent_free(AGENT *agent) {
  if (agent) {
    string_free(agent->ident);
    if (agent->sock) {
      agent_close(agent);
      ssh_socket_free(agent->sock);
    }
    SAFE_FREE(agent);
  }
}

static int agent_connect(SSH_SESSION *session) {
  const char *auth_sock = NULL;

  if (session == NULL || session->agent == NULL) {
    return -1;
  }

  auth_sock = getenv("SSH_AUTH_SOCK");

  if (auth_sock && *auth_sock) {
    if (ssh_socket_unix(session->agent->sock, auth_sock) < 0) {
      return -1;
    }
    return 0;
  }

  return -1;
}

static int agent_decode_reply(int type) {
  switch (type) {
    case SSH_AGENT_FAILURE:
    case SSH2_AGENT_FAILURE:
    case SSH_COM_AGENT2_FAILURE:
      ssh_say(1, "SSH_AGENT_FAILURE\n");
      return 0;
    case SSH_AGENT_SUCCESS:
      return 1;
    default:
      /* TODO: fatal */
      break;
  }

  return -1;
}

static int agent_talk(struct ssh_session *session,
    struct buffer_struct *request, struct buffer_struct *reply) {
  size_t len = 0;
  unsigned char payload[1024] = {0};

  len = buffer_get_len(request);
  ssh_say(2, "agent_talk - len of request: %u\n", len);
  agent_put_u32(payload, len);

#if 0
  /* send length and then the request packet */
  if (ssh_socket_completewrite(session->agent->sock, payload, 4) == SSH_OK) {
    buffer_get_data(request, payload, len);
    fprintf(stderr, "agent_talk - sending request, payload = %u\n", payload[0]);
    if (ssh_socket_completewrite(session->agent->sock, payload, len)
        != SSH_OK) {
      return -1;
    }
  } else {
    return -1;
  }
#endif
  /* send length and then the request packet */
  if (atomicio(session->agent->sock, payload, 4, 0) == 4) {
    buffer_get_data(request, payload, len);
    ssh_say(2, "agent_talk - sending request, payload = %u\n", payload[0]);
    if (atomicio(session->agent->sock, payload, len, 0)
        != len) {
      return -1;
    }
  } else {
    return -1;
  }

  session->blocking = 0;

#if 0
  /* wait for response, read the length of the response packet */
  if (ssh_socket_read(session->agent->sock, payload, 4) != SSH_OK) {
    fprintf(stderr, "agent_talk - error: %s\n", ssh_get_error(session));
    return -1;
  }
#endif
  /* wait for response, read the length of the response packet */
  if (atomicio(session->agent->sock, payload, 4, 1) != 4) {
    return -1;
  }

  len = agent_get_u32(payload);
  if (len > 256 * 1024) {
    return -1;
  }
  ssh_say(2, "agent_talk - response length: %u\n", len);

  while (len > 0) {
    size_t n = len;
    if (n > sizeof(payload)) {
      n = sizeof(payload);
    }
    if (atomicio(session->agent->sock, payload, n, 1) != n) {
      ssh_say(1, "Error reading response from authentication socket.");
      return -1;
    }
    buffer_add_data(reply, payload, n);
    len -= n;
  }

  return 0;
}

int agent_ident_count(SSH_SESSION *session) {
  BUFFER *request = NULL;
  BUFFER *reply = NULL;
  unsigned int type = 0;
  unsigned int c1 = 0, c2 = 0;
  unsigned char buf[4] = {0};

  switch (session->version) {
    case 1:
      c1 = SSH_AGENTC_REQUEST_RSA_IDENTITIES;
      c2 = SSH_AGENT_RSA_IDENTITIES_ANSWER;
      break;
    case 2:
      c1 = SSH2_AGENTC_REQUEST_IDENTITIES;
      c2 = SSH2_AGENT_IDENTITIES_ANSWER;
      break;
    default:
      return 0;
  }

  /* send message to the agent requesting the list of identities */
  request = buffer_new();
  buffer_add_u8(request, c1);

  reply = buffer_new();

  if (agent_talk(session, request, reply) < 0) {
    buffer_free(request);
    return 0;
  }
  buffer_free(request);

  /* get message type and verify the answer */
  buffer_get_u8(reply, (u8 *) &type);
  ssh_say(2, "agent_ident_count - answer type: %d, expected answer: %d\n",
      type, c2);
  if (agent_failed(type)) {
    return 0;
  } else if (type != c2) {
    /* TODO: fatal, set ssh error? */
    return -1;
  }

  buffer_get_u32(reply, (u32 *) buf);
  session->agent->count = agent_get_u32(buf);
  ssh_say(2, "agent_ident_count - count: %d\n", session->agent->count);
  if (session->agent->count > 1024) {
    /* TODO: fatal, set ssh error? */
    return -1;
  }

  return session->agent->count;
}

int agent_running(SSH_SESSION *session) {
  if (session == NULL || session->agent == NULL) {
    return 0;
  }

  if (ssh_socket_is_open(session->agent->sock)) {
    return 1;
  } else {
    if (agent_connect(session) < 0) {
      return 0;
    } else {
      return 1;
    }
  }

  return 0;
}

#endif /* _WIN32 */

