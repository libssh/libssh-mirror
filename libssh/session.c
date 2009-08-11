/*
 * session.c - non-networking functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2005-2008 by Aris Adamantiadis
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

#include <string.h>
#include <stdlib.h>
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/server.h"
#define FIRST_CHANNEL 42 // why not ? it helps to find bugs.

/** \defgroup ssh_session SSH Session
 * \brief functions that manage a session
 */
/** \addtogroup ssh_session
 * @{ */

/** \brief creates a new ssh session
 * \returns new ssh_session pointer
 */
SSH_SESSION *ssh_new(void) {
  SSH_SESSION *session;

  session = malloc(sizeof (SSH_SESSION));
  if (session == NULL) {
    return NULL;
  }

  memset(session, 0, sizeof(SSH_SESSION));

  session->next_crypto = crypto_new();
  if (session->next_crypto == NULL) {
    goto err;
  }

  session->maxchannel = FIRST_CHANNEL;
  session->socket = ssh_socket_new(session);
  if (session->socket == NULL) {
    goto err;
  }

  session->alive = 0;
  session->auth_methods = 0;
  session->blocking = 1;
  session->log_indent = 0;

  session->out_buffer = buffer_new();
  if (session->out_buffer == NULL) {
    goto err;
  }

  session->in_buffer=buffer_new();
  if (session->in_buffer == NULL) {
    goto err;
  }

#ifndef _WIN32
    session->agent = agent_new(session);
    if (session->agent == NULL) {
      goto err;
    }
#endif /* _WIN32 */
    return session;

err:
    ssh_cleanup(session);
    return NULL;
}

void ssh_cleanup(SSH_SESSION *session) {
  int i;
  enter_function();

  if (session == NULL) {
    return;
  }

  SAFE_FREE(session->serverbanner);
  SAFE_FREE(session->clientbanner);
  SAFE_FREE(session->banner);
  buffer_free(session->in_buffer);
  buffer_free(session->out_buffer);
  session->in_buffer=session->out_buffer=NULL;
  crypto_free(session->current_crypto);
  crypto_free(session->next_crypto);
  ssh_socket_free(session->socket);
  /* delete all channels */
  while (session->channels) {
    channel_free(session->channels);
  }
#ifndef _WIN32
  agent_free(session->agent);
#endif /* _WIN32 */
  if (session->client_kex.methods) {
    for (i = 0; i < 10; i++) {
      SAFE_FREE(session->client_kex.methods[i]);
    }
  }

  if (session->server_kex.methods) {
    for (i = 0; i < 10; i++) {
      SAFE_FREE(session->server_kex.methods[i]);
    }
  }
  SAFE_FREE(session->client_kex.methods);
  SAFE_FREE(session->server_kex.methods);

  privatekey_free(session->dsa_key);
  privatekey_free(session->rsa_key);
  ssh_message_free(session->ssh_message);
  ssh_options_free(session->options);

  /* burn connection, it could hang sensitive datas */
  memset(session,'X',sizeof(SSH_SESSION));

  SAFE_FREE(session);
  /* FIXME: leave_function(); ??? */
}

/** \brief disconnect impolitely from remote host
 * \param session current ssh session
 */
void ssh_silent_disconnect(SSH_SESSION *session) {
  enter_function();

  if (session == NULL) {
    return;
  }

  ssh_socket_close(session->socket);
  session->alive = 0;
  ssh_disconnect(session);
  /* FIXME: leave_function(); ??? */
}

/** \brief set the options for the current session
 * \param session ssh session
 * \param options options structure
 * \see ssh_new()
 * \see ssh_options_new()
 */
void ssh_set_options(SSH_SESSION *session, SSH_OPTIONS *options) {
  if (session == NULL || options == NULL) {
    return;
  }

  session->options = options;
  session->log_verbosity = options->log_verbosity;
}

/** \brief set the session in blocking/nonblocking mode
 * \param session ssh session
 * \param blocking zero for nonblocking mode
 * \bug nonblocking code is in development and won't work as expected
 */
void ssh_set_blocking(SSH_SESSION *session, int blocking) {
  if (session == NULL) {
    return;
  }

  session->blocking = blocking ? 1 : 0;
}

/** In case you'd need the file descriptor of the connection
 * to the server/client
 * \brief recover the fd of connection
 * \param session ssh session
 * \return file descriptor of the connection, or -1 if it is
 * not connected
 */
socket_t ssh_get_fd(SSH_SESSION *session) {
  if (session == NULL) {
    return -1;
  }

  return ssh_socket_get_fd(session->socket);
}

/** \brief say to the session it has data to read on the file descriptor without blocking
 * \param session ssh session
 */
void ssh_set_fd_toread(SSH_SESSION *session) {
  if (session == NULL) {
    return;
  }

  ssh_socket_set_toread(session->socket);
}

/** \brief say the session it may write to the file descriptor without blocking
 * \param session ssh session
 */
void ssh_set_fd_towrite(SSH_SESSION *session) {
  if (session == NULL) {
    return;
  }

  ssh_socket_set_towrite(session->socket);
}

/** \brief say the session it has an exception to catch on the file descriptor
 * \param session ssh session
 */
void ssh_set_fd_except(SSH_SESSION *session) {
  if (session == NULL) {
    return;
  }

  ssh_socket_set_except(session->socket);
}

/** \warning I don't remember if this should be internal or not
 */
/* looks if there is data to read on the socket and parse it. */
int ssh_handle_packets(SSH_SESSION *session) {
  int w = 0;
  int e = 0;
  int rc = -1;

  enter_function();

  do {
    rc = ssh_socket_poll(session->socket, &w, &e);
    if (rc <= 0) {
      /* error or no data available */
      leave_function();
      return rc;
    }

    /* if an exception happened, it will be trapped by packet_read() */
    if ((packet_read(session) != SSH_OK) ||
        (packet_translate(session) != SSH_OK)) {
      leave_function();
      return -1;
    }

    packet_parse(session);
  } while(rc > 0);

  leave_function();
  return rc;
}

/**
 * @brief Get session status
 *
 * @param session       The ssh session to use.
 *
 * @returns A bitmask including SSH_CLOSED, SSH_READ_PENDING or SSH_CLOSED_ERROR
 *          which respectively means the session is closed, has data to read on
 *          the connection socket and session was closed due to an error.
 */
int ssh_get_status(SSH_SESSION *session) {
  int socketstate;
  int r = 0;

  if (session == NULL) {
    return 0;
  }

  socketstate = ssh_socket_get_status(session->socket);

  if (session->closed) {
    r |= SSH_CLOSED;
  }
  if (socketstate & SSH_READ_PENDING) {
    r |= SSH_READ_PENDING;
  }
  if (session->closed && (socketstate & SSH_CLOSED_ERROR)) {
    r |= SSH_CLOSED_ERROR;
  }

  return r;
}

/** \brief get the disconnect message from the server
 * \param session ssh session
 * \return message sent by the server along with the disconnect, or NULL in which case the reason of the disconnect may be found with ssh_get_error.
 * \see ssh_get_error()
 */
const char *ssh_get_disconnect_message(SSH_SESSION *session) {
  if (session == NULL) {
    return NULL;
  }

  if (!session->closed) {
    ssh_set_error(session, SSH_REQUEST_DENIED,
        "Connection not closed yet");
  } else if(session->closed_by_except) {
    ssh_set_error(session, SSH_REQUEST_DENIED,
        "Connection closed by socket error");
  } else if(!session->discon_msg) {
    ssh_set_error(session, SSH_FATAL,
        "Connection correctly closed but no disconnect message");
  } else {
    return session->discon_msg;
  }

  return NULL;
}

/**
 * @brief Get the protocol version of the session.
 *
 * @param session       The ssh session to use.
 *
 * @return 1 or 2, for ssh1 or ssh2, < 0 on error.
 */
int ssh_get_version(SSH_SESSION *session) {
  if (session == NULL) {
    return -1;
  }

  return session->version;
}

/** @} */
/* vim: set ts=2 sw=2 et cindent: */
