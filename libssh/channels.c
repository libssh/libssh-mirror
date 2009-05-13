/*
 * channels.c - SSH channel functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
 * Copyright (c) 2009      by Andreas Schneider <mail@cynapses.org>
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
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include "libssh/priv.h"
#include "libssh/ssh2.h"

#define WINDOWBASE 128000
#define WINDOWLIMIT (WINDOWBASE/2)

/**
 * @defgroup ssh_channel SSH Channels
 * @brief Functions that manage a channel.
 */

/**
 * @addtogroup ssh_channel
 * @{
 */

/**
 * @brief Allocate a new channel.
 *
 * @param session       The ssh session to use.
 *
 * @return A pointer to a newly allocated channel, NULL on error.
 */
CHANNEL *channel_new(SSH_SESSION *session) {
  CHANNEL *channel = NULL;

  channel = malloc(sizeof(CHANNEL));
  if (channel == NULL) {
    return NULL;
  }
  memset(channel,0,sizeof(CHANNEL));

  channel->stdout_buffer = buffer_new();
  if (channel->stdout_buffer == NULL) {
    SAFE_FREE(channel);
    return NULL;
  }

  channel->stderr_buffer = buffer_new();
  if (channel->stderr_buffer == NULL) {
    SAFE_FREE(channel);
    return NULL;
  }

  channel->session = session;
  channel->version = session->version;
  channel->exit_status = -1;

  if(session->channels == NULL) {
    session->channels = channel;
    channel->next = channel->prev = channel;
    return channel;
  }
  channel->next = session->channels;
  channel->prev = session->channels->prev;
  channel->next->prev = channel;
  channel->prev->next = channel;

  return channel;
}

/**
 * @internal
 *
 * @brief Create a new channel identifier.
 *
 * @param  session      The SSH session to use.
 *
 * @return The new channel identifier.
 */
u32 ssh_channel_new_id(SSH_SESSION *session) {
  return ++(session->maxchannel);
}

static int channel_open(CHANNEL *channel, const char *type_c, int window,
    int maxpacket, BUFFER *payload) {
  SSH_SESSION *session = channel->session;
  STRING *type = NULL;
  u32 tmp = 0;

  enter_function();

  channel->local_channel = ssh_channel_new_id(session);
  channel->local_maxpacket = maxpacket;
  channel->local_window = window;

  ssh_log(session, SSH_LOG_RARE,
      "Creating a channel %d with %d window and %d max packet",
      channel->local_channel, window, maxpacket);

  type = string_from_char(type_c);
  if (type == NULL) {
    leave_function();
    return -1;
  }

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_CHANNEL_OPEN) < 0 ||
      buffer_add_ssh_string(session->out_buffer,type) < 0 ||
      buffer_add_u32(session->out_buffer, htonl(channel->local_channel)) < 0 ||
      buffer_add_u32(session->out_buffer, htonl(channel->local_window)) < 0 ||
      buffer_add_u32(session->out_buffer, htonl(channel->local_maxpacket)) < 0) {
    string_free(type);
    leave_function();
    return -1;
  }

  string_free(type);

  if (payload != NULL) {
    if (buffer_add_buffer(session->out_buffer, payload) < 0) {
      leave_function();
      return -1;
    }
  }

  if (packet_send(session) != SSH_OK) {
    leave_function();
    return -1;
  }

  ssh_log(session, SSH_LOG_RARE,
      "Sent a SSH_MSG_CHANNEL_OPEN type %s for channel %d",
      type_c, channel->local_channel);

  if (packet_wait(session, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, 1) != SSH_OK) {
    leave_function();
    return -1;
  }

  switch(session->in_packet.type) {
    case SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
      buffer_get_u32(session->in_buffer, &tmp);

      if (channel->local_channel != ntohl(tmp)) {
        ssh_set_error(session, SSH_FATAL,
            "Server answered with sender channel number %lu instead of given %u",
            (long unsigned int) ntohl(tmp),
            channel->local_channel);
        leave_function();
        return -1;
      }
      buffer_get_u32(session->in_buffer, &tmp);
      channel->remote_channel = ntohl(tmp);

      buffer_get_u32(session->in_buffer, &tmp);
      channel->remote_window = ntohl(tmp);

      buffer_get_u32(session->in_buffer,&tmp);
      channel->remote_maxpacket=ntohl(tmp);

      ssh_log(session, SSH_LOG_PROTOCOL,
          "Received a CHANNEL_OPEN_CONFIRMATION for channel %d:%d",
          channel->local_channel,
          channel->remote_channel);
      ssh_log(session, SSH_LOG_PROTOCOL,
          "Remote window : %lu, maxpacket : %lu",
          (long unsigned int) channel->remote_window,
          (long unsigned int) channel->remote_maxpacket);

      channel->open = 1;
      leave_function();
      return 0;
    case SSH2_MSG_CHANNEL_OPEN_FAILURE:
      {
        STRING *error_s;
        char *error;
        u32 code;

        buffer_get_u32(session->in_buffer, &tmp);
        buffer_get_u32(session->in_buffer, &code);

        error_s = buffer_get_ssh_string(session->in_buffer);
        error = string_to_char(error_s);
        string_free(error_s);
        if (error == NULL) {
          leave_function();
          return -1;
        }

        ssh_set_error(session, SSH_REQUEST_DENIED,
            "Channel opening failure: channel %u error (%lu) %s",
            channel->local_channel,
            (long unsigned int) ntohl(code),
            error);
        SAFE_FREE(error);

        leave_function();
        return -1;
      }
    default:
      ssh_set_error(session, SSH_FATAL,
          "Received unknown packet %d\n", session->in_packet.type);
      leave_function();
      return -1;
  }

  leave_function();
  return -1;
}

/* get ssh channel from local session? */
CHANNEL *ssh_channel_from_local(SSH_SESSION *session, u32 id) {
  CHANNEL *initchan = session->channels;
  CHANNEL *channel;

  /* We assume we are always the local */
  if (initchan == NULL) {
    return NULL;
  }

  for (channel = initchan; channel->local_channel != id;
      channel=channel->next) {
    if (channel->next == initchan) {
      return NULL;
    }
  }

  return channel;
}

static int grow_window(SSH_SESSION *session, CHANNEL *channel, int minimumsize) {
  u32 new_window = minimumsize > WINDOWBASE ? minimumsize : WINDOWBASE;

  enter_function();

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_CHANNEL_WINDOW_ADJUST) < 0 ||
      buffer_add_u32(session->out_buffer, htonl(channel->remote_channel)) < 0 ||
      buffer_add_u32(session->out_buffer, htonl(new_window)) < 0) {
    goto error;
  }

  if (packet_send(session) != SSH_OK) {
    /* FIXME should we fail here or not? */
    leave_function();
    return 1;
  }

  ssh_log(session, SSH_LOG_PROTOCOL,
      "growing window (channel %d:%d) to %d bytes",
      channel->local_channel,
      channel->remote_channel,
      channel->local_window + new_window);

  channel->local_window += new_window;

  leave_function();
  return 0;
error:
  buffer_free(session->out_buffer);

  leave_function();
  return -1;
}

static CHANNEL *channel_from_msg(SSH_SESSION *session) {
  CHANNEL *channel;
  u32 chan;

  if (buffer_get_u32(session->in_buffer, &chan) != sizeof(u32)) {
    ssh_set_error(session, SSH_FATAL,
        "Getting channel from message: short read");
    return NULL;
  }

  channel = ssh_channel_from_local(session, ntohl(chan));
  if (channel == NULL) {
    ssh_set_error(session, SSH_FATAL,
        "Server specified invalid channel %lu",
        (long unsigned int) ntohl(chan));
  }

  return channel;
}

static void channel_rcv_change_window(SSH_SESSION *session) {
  CHANNEL *channel;
  u32 bytes;
  int rc;

  enter_function();

  channel = channel_from_msg(session);
  if (channel == NULL) {
    ssh_log(session, SSH_LOG_FUNCTIONS, ssh_get_error(session));
  }

  rc = buffer_get_u32(session->in_buffer, &bytes);
  if (channel == NULL || rc != sizeof(u32)) {
    ssh_log(session, SSH_LOG_PACKET,
        "Error getting a window adjust message: invalid packet");
    leave_function();
    return;
  }

  bytes = ntohl(bytes);
  ssh_log(session, SSH_LOG_PROTOCOL,
      "Adding %d bytes to channel (%d:%d) (from %d bytes)",
      bytes,
      channel->local_channel,
      channel->remote_channel,
      channel->remote_window);

  channel->remote_window += bytes;

  leave_function();
}

/* is_stderr is set to 1 if the data are extended, ie stderr */
static void channel_rcv_data(SSH_SESSION *session,int is_stderr) {
  CHANNEL *channel;
  STRING *str;
  size_t len;

  enter_function();

  channel = channel_from_msg(session);
  if (channel == NULL) {
    ssh_log(session, SSH_LOG_FUNCTIONS,
        "%s", ssh_get_error(session));
    leave_function();
    return;
  }

  if (is_stderr) {
    u32 ignore;
    /* uint32 data type code. we can ignore it */
    buffer_get_u32(session->in_buffer, &ignore);
  }

  str = buffer_get_ssh_string(session->in_buffer);
  if (str == NULL) {
    ssh_log(session, SSH_LOG_PACKET, "Invalid data packet!");
    leave_function();
    return;
  }
  len = string_len(str);

  ssh_log(session, SSH_LOG_PROTOCOL,
      "Channel receiving %zu bytes data in %d (local win=%d remote win=%d)",
      len,
      is_stderr,
      channel->local_window,
      channel->remote_window);

  /* What shall we do in this case? Let's accept it anyway */
  if (len > channel->local_window) {
    ssh_log(session, SSH_LOG_RARE,
        "Data packet too big for our window(%zu vs %d)",
        len,
        channel->local_window);
  }

  if (channel_default_bufferize(channel, str->string, len,
        is_stderr) < 0) {
    string_free(str);
    leave_function();
    return;
  }

  if (len <= channel->local_window) {
    channel->local_window -= len;
  } else {
    channel->local_window = 0; /* buggy remote */
  }

  ssh_log(session, SSH_LOG_PROTOCOL,
      "Channel windows are now (local win=%d remote win=%d)",
      channel->local_window,
      channel->remote_window);

  string_free(str);
  leave_function();
}

static void channel_rcv_eof(SSH_SESSION *session) {
  CHANNEL *channel;

  enter_function();

  channel = channel_from_msg(session);
  if (channel == NULL) {
    ssh_log(session, SSH_LOG_FUNCTIONS, ssh_get_error(session));
    leave_function();
    return;
  }

  ssh_log(session, SSH_LOG_PACKET,
      "Received eof on channel (%d:%d)",
      channel->local_channel,
      channel->remote_channel);
  /* channel->remote_window = 0; */
  channel->remote_eof = 1;

  leave_function();
}

static void channel_rcv_close(SSH_SESSION *session) {
  CHANNEL *channel;

  enter_function();

  channel = channel_from_msg(session);
  if (channel == NULL) {
    ssh_log(session, SSH_LOG_FUNCTIONS, ssh_get_error(session));
    leave_function();
    return;
  }

  ssh_log(session, SSH_LOG_PACKET,
      "Received close on channel (%d:%d)",
      channel->local_channel,
      channel->remote_channel);

  if ((channel->stdout_buffer &&
        buffer_get_rest_len(channel->stdout_buffer) > 0) ||
      (channel->stderr_buffer &&
       buffer_get_rest_len(channel->stderr_buffer) > 0)) {
    channel->delayed_close = 1;
  } else {
    channel->open = 0;
  }

  if (channel->remote_eof == 0) {
    ssh_log(session, SSH_LOG_PACKET,
        "Remote host not polite enough to send an eof before close");
  }
  channel->remote_eof = 1;
  /*
   * The remote eof doesn't break things if there was still data into read
   * buffer because the eof is ignored until the buffer is empty.
   */

  leave_function();
}

static void channel_rcv_request(SSH_SESSION *session) {
  CHANNEL *channel;
  STRING *request_s;
  char *request;
  u32 status;

  enter_function();

  channel = channel_from_msg(session);
  if (channel == NULL) {
    ssh_log(session, SSH_LOG_FUNCTIONS, ssh_get_error(session));
    leave_function();
    return;
  }

  request_s = buffer_get_ssh_string(session->in_buffer);
  if (request_s == NULL) {
    ssh_log(session, SSH_LOG_PACKET, "Invalid MSG_CHANNEL_REQUEST");
    leave_function();
    return;
  }

  request = string_to_char(request_s);
  string_free(request_s);
  if (request == NULL) {
    leave_function();
    return;
  }

  buffer_get_u8(session->in_buffer, (u8 *) &status);

  if (strcmp(request,"exit-status") == 0) {
    SAFE_FREE(request);
    ssh_log(session, SSH_LOG_PACKET, "received exit-status");
    buffer_get_u32(session->in_buffer, &status);
    channel->exit_status = ntohl(status);

    leave_function();
    return ;
  }

  if (strcmp(request, "exit-signal") == 0) {
    const char *core = "(core dumped)";
    STRING *signal_s;
    char *signal;
    u8 i;

    SAFE_FREE(request);

    signal_s = buffer_get_ssh_string(session->in_buffer);
    if (signal_s == NULL) {
      ssh_log(session, SSH_LOG_PACKET, "Invalid MSG_CHANNEL_REQUEST");
      leave_function();
      return;
    }

    signal = string_to_char(signal_s);
    string_free(signal_s);
    if (signal == NULL) {
      leave_function();
      return;
    }

    buffer_get_u8(session->in_buffer, &i);
    if (i == 0) {
      core = "";
    }

    ssh_log(session, SSH_LOG_PACKET,
        "Remote connection closed by signal SIG %s %s", signal, core);
    SAFE_FREE(signal);

    leave_function();
    return;
  }
  ssh_log(session, SSH_LOG_PACKET, "Unknown request %s", request);
  SAFE_FREE(request);

  leave_function();
}

/*
 * channel_handle() is called by packet_wait(), for example when there is
 * channel informations to handle.
 */
void channel_handle(SSH_SESSION *session, int type){
  enter_function();

  ssh_log(session, SSH_LOG_PROTOCOL, "Channel_handle(%d)", type);

  switch(type) {
    case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
      channel_rcv_change_window(session);
      break;
    case SSH2_MSG_CHANNEL_DATA:
      channel_rcv_data(session,0);
      break;
    case SSH2_MSG_CHANNEL_EXTENDED_DATA:
      channel_rcv_data(session,1);
      break;
    case SSH2_MSG_CHANNEL_EOF:
      channel_rcv_eof(session);
      break;
    case SSH2_MSG_CHANNEL_CLOSE:
      channel_rcv_close(session);
      break;
    case SSH2_MSG_CHANNEL_REQUEST:
      channel_rcv_request(session);
      break;
    default:
      ssh_log(session, SSH_LOG_FUNCTIONS,
          "Unexpected message %d", type);
  }

  leave_function();
}

/*
 * When data has been received from the ssh server, it can be applied to the
 * known user function, with help of the callback, or inserted here
 *
 * FIXME is the window changed?
 */
int channel_default_bufferize(CHANNEL *channel, void *data, int len,
    int is_stderr) {
  struct ssh_session *session = channel->session;

  ssh_log(session, SSH_LOG_RARE,
      "placing %d bytes into channel buffer (stderr=%d)", len, is_stderr);
  if (is_stderr == 0) {
    /* stdout */
    if (channel->stdout_buffer == NULL) {
      channel->stdout_buffer = buffer_new();
      if (channel->stdout_buffer == NULL) {
        return -1;
      }
    }

    if (buffer_add_data(channel->stdout_buffer, data, len) < 0) {
      buffer_free(channel->stdout_buffer);
      return -1;
    }
  } else {
    /* stderr */
    if (channel->stderr_buffer == NULL) {
      channel->stderr_buffer = buffer_new();
      if (channel->stderr_buffer == NULL) {
        return -1;
      }
    }

    if (buffer_add_data(channel->stderr_buffer, data, len) < 0) {
      buffer_free(channel->stderr_buffer);
      return -1;
    }
  }

  return 0;
}

/**
 * @brief Open a session channel (suited for a shell, not TCP forwarding).
 *
 * @param channel       An allocated channel.
 *
 * @return SSH_OK on success\n
 *         SSH_ERROR on error.
 *
 * @see channel_open_forward()
 * @see channel_request_env()
 * @see channel_request_shell()
 * @see channel_request_exec()
 */
int channel_open_session(CHANNEL *channel) {
#ifdef HAVE_SSH1
  if (channel->session->version == 1) {
    return channel_open_session1(channel);
  }
#endif

  return channel_open(channel,"session",64000,32000,NULL);
}

/**
 * @brief Open a TCP/IP forwarding channel.
 *
 * @param channel       An allocated channel.
 *
 * @param remotehost    The remote host to connected (host name or IP).
 *
 * @param remoteport    The remote port.
 *
 * @param sourcehost    The source host (your local computer). It's facultative
 *                      and for logging purpose.
 *
 * @param localport     The source port (your local computer). It's facultative
 *                      and for logging purpose.
 *
 * @return SSH_OK on success\n
 *         SSH_ERROR on error
 */
int channel_open_forward(CHANNEL *channel, const char *remotehost,
    int remoteport, const char *sourcehost, int localport) {
  SSH_SESSION *session = channel->session;
  BUFFER *payload = NULL;
  STRING *str = NULL;
  int rc = SSH_ERROR;

  enter_function();

  payload = buffer_new();
  if (payload == NULL) {
    goto error;
  }
  str = string_from_char(remotehost);
  if (str == NULL) {
    goto error;
  }

  if (buffer_add_ssh_string(payload, str) < 0 ||
      buffer_add_u32(payload,htonl(remoteport)) < 0) {
    goto error;
  }

  string_free(str);
  str = string_from_char(sourcehost);
  if (str == NULL) {
    goto error;
  }

  if (buffer_add_ssh_string(payload, str) < 0 ||
      buffer_add_u32(payload,htonl(localport)) < 0) {
    goto error;
  }

  rc = channel_open(channel, "direct-tcpip", 64000, 32000, payload);

error:
  buffer_free(payload);
  string_free(str);

  leave_function();
  return rc;
}

/**
 * @brief Close and free a channel.
 *
 * @param channel       The channel to free.
 *
 * @warning Any data unread on this channel will be lost.
 */
void channel_free(CHANNEL *channel) {
  SSH_SESSION *session = channel->session;
  enter_function();

  if (channel == NULL) {
    leave_function();
    return;
  }

  if (session->alive && channel->open) {
    channel_close(channel);
  }

  /* handle the "my channel is first on session list" case */
  if (session->channels == channel) {
    session->channels = channel->next;
  }

  /* handle the "my channel is the only on session list" case */
  if (channel->next == channel) {
    session->channels = NULL;
  } else {
    channel->prev->next = channel->next;
    channel->next->prev = channel->prev;
  }

  buffer_free(channel->stdout_buffer);
  buffer_free(channel->stderr_buffer);

  /* debug trick to catch use after frees */
  memset(channel, 'X', sizeof(CHANNEL));
  SAFE_FREE(channel);

  leave_function();
}

/**
 * @brief Send an end of file on the channel.
 *
 * This doesn't close the channel. You may still read from it but not write.
 *
 * @param channel       The channel to send the eof to.
 *
 * @return SSH_SUCCESS on success\n
 *         SSH_ERROR on error\n
 *
 * @see channel_close()
 * @see channel_free()
 */
int channel_send_eof(CHANNEL *channel){
  SSH_SESSION *session = channel->session;
  int rc = SSH_ERROR;

  enter_function();

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_CHANNEL_EOF) < 0) {
    goto error;
  }
  if (buffer_add_u32(session->out_buffer,htonl(channel->remote_channel)) < 0) {
    goto error;
  }
  rc = packet_send(session);
  ssh_log(session, SSH_LOG_PACKET,
      "Sent a EOF on client channel (%d:%d)",
      channel->local_channel,
      channel->remote_channel);

  channel->local_eof = 1;

  leave_function();
  return rc;
error:
  buffer_free(session->out_buffer);

  leave_function();
  return rc;
}

/**
 * @brief Close a channel.
 *
 * This sends an end of file and then closes the channel. You won't be able
 * to recover any data the server was going to send or was in buffers.
 *
 * @param channel       The channel to close.
 *
 * @return SSH_SUCCESS on success\n
 *         SSH_ERROR on error
 *
 * @see channel_free()
 * @see channel_eof()
 */
int channel_close(CHANNEL *channel){
  SSH_SESSION *session = channel->session;
  int rc = 0;

  enter_function();

  if (channel->local_eof == 0) {
    rc = channel_send_eof(channel);
  }

  if (rc != SSH_OK) {
    leave_function();
    return rc;
  }

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_CHANNEL_CLOSE) < 0 ||
      buffer_add_u32(session->out_buffer, htonl(channel->remote_channel)) < 0) {
    goto error;
  }

  rc = packet_send(session);
  ssh_log(session, SSH_LOG_PACKET,
      "Sent a close on client channel (%d:%d)",
      channel->local_channel,
      channel->remote_channel);

  if(rc == SSH_OK) {
    channel->open = 0;
  }

  leave_function();
  return rc;
error:
  buffer_free(session->out_buffer);

  leave_function();
  return rc;
}

/**
 * @brief Blocking write on channel.
 *
 * @param channel       The channel to write to.
 *
 * @param data          A pointer to the data to write.
 *
 * @param len           The length of the buffer to write to.
 *
 * @return The number of bytes written, SSH_ERROR on error.
 *
 * @see channel_read()
 */
int channel_write(CHANNEL *channel, const void *data, u32 len) {
  SSH_SESSION *session = channel->session;
  int origlen = len;
  int effectivelen;

  enter_function();

  if (channel->local_eof) {
    ssh_set_error(session, SSH_REQUEST_DENIED,
        "Can't write to channel %d:%d  after EOF was sent",
        channel->local_channel,
        channel->remote_channel);
    leave_function();
    return -1;
  }

  if (channel->open == 0 || channel->delayed_close != 0) {
    ssh_set_error(session, SSH_REQUEST_DENIED, "Remote channel is closed");
    leave_function();
    return -1;
  }

#ifdef HAVE_SSH1
  if (channel->version == 1) {
    int rc = channel_write1(channel, data, len);
    leave_function();
    return rc;
  }
#endif

  while (len > 0) {
    if (channel->remote_window < len) {
      ssh_log(session, SSH_LOG_PROTOCOL,
          "Remote window is %d bytes. going to write %d bytes",
          channel->remote_window,
          len);
      ssh_log(session, SSH_LOG_PROTOCOL,
          "Waiting for a growing window message...");
      /* What happens when the channel window is zero? */
      while(channel->remote_window == 0) {
        /* parse every incoming packet */
        packet_wait(channel->session, 0, 0);
      }
      effectivelen = len > channel->remote_window ? channel->remote_window : len;
    } else {
      effectivelen = len;
    }

    if (buffer_add_u8(session->out_buffer, SSH2_MSG_CHANNEL_DATA) < 0 ||
        buffer_add_u32(session->out_buffer,
          htonl(channel->remote_channel)) < 0 ||
        buffer_add_u32(session->out_buffer, htonl(effectivelen)) < 0 ||
        buffer_add_data(session->out_buffer, data, effectivelen) < 0) {
      goto error;
    }

    if (packet_send(session) != SSH_OK) {
      leave_function();
      return SSH_ERROR;
    }

    ssh_log(session, SSH_LOG_RARE,
        "channel_write wrote %d bytes", effectivelen);

    channel->remote_window -= effectivelen;
    len -= effectivelen;
    data += effectivelen;
  }

  leave_function();
  return origlen;
error:
  buffer_free(session->out_buffer);

  leave_function();
  return SSH_ERROR;
}

/**
 * @brief Check if the channel is open or not.
 *
 * @param channel       The channel to check.
 *
 * @return 0 if channel is closed, nonzero otherwise.
 *
 * @see channel_is_closed()
 */
int channel_is_open(CHANNEL *channel) {
  return (channel->open != 0 && channel->session->alive != 0);
}

/**
 * @brief Check if the channel is closed or not.
 *
 * @param channel       The channel to check.
 *
 * @return 0 if channel is opened, nonzero otherwise.
 *
 * @see channel_is_open()
 */
int channel_is_closed(CHANNEL *channel) {
  return (channel->open == 0 || channel->session->alive == 0);
}

/**
 * @brief Check if remote has sent an EOF.
 *
 * @param channel       The channel to check.
 *
 * @return 0 if there is no EOF, nonzero otherwise.
 */
int channel_is_eof(CHANNEL *channel) {
  if ((channel->stdout_buffer &&
        buffer_get_rest_len(channel->stdout_buffer) > 0) ||
      (channel->stderr_buffer &&
       buffer_get_rest_len(channel->stderr_buffer) > 0)) {
    return 0;
  }

  return (channel->remote_eof != 0);
}

/**
 * @brief Put the channel into blocking or nonblocking mode.
 *
 * @param channel       The channel to use.
 *
 * @param blocking      A boolean for blocking or nonblocking.
 *
 * @bug This functionnality is still under development and
 *      doesn't work correctly.
 */
void channel_set_blocking(CHANNEL *channel, int blocking) {
  channel->blocking = (blocking == 0 ? 0 : 1);
}

static int channel_request(CHANNEL *channel, const char *request,
    BUFFER *buffer, int reply) {
  SSH_SESSION *session = channel->session;
  STRING *req = NULL;
  int rc = SSH_ERROR;

  enter_function();

  req = string_from_char(request);
  if (req == NULL) {
    goto error;
  }

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_CHANNEL_REQUEST) < 0 ||
      buffer_add_u32(session->out_buffer, htonl(channel->remote_channel)) < 0 ||
      buffer_add_ssh_string(session->out_buffer, req) < 0 ||
      buffer_add_u8(session->out_buffer, reply == 0 ? 0 : 1) < 0) {
    goto error;
  }
  string_free(req);

  if (buffer != NULL) {
    if (buffer_add_data(session->out_buffer, buffer_get(buffer),
        buffer_get_len(buffer)) < 0) {
      goto error;
    }
  }

  if (packet_send(session) != SSH_OK) {
    leave_function();
    return rc;
  }

  ssh_log(session, SSH_LOG_RARE,
      "Sent a SSH_MSG_CHANNEL_REQUEST %s", request);
  if (reply == 0) {
    leave_function();
    return SSH_OK;
  }

  rc = packet_wait(session, SSH2_MSG_CHANNEL_SUCCESS, 1);
  if (rc) {
    if (session->in_packet.type == SSH2_MSG_CHANNEL_FAILURE) {
      ssh_log(session, SSH_LOG_PACKET,
          "%s channel request failed", request);
      ssh_set_error(session, SSH_REQUEST_DENIED,
          "Channel request %s failed", request);
    } else {
      ssh_log(session, SSH_LOG_RARE,
          "Received an unexpected %d message", session->in_packet.type);
    }
  } else {
    ssh_log(session, SSH_LOG_RARE, "Received a SUCCESS");
  }

  leave_function();
  return rc;
error:
  buffer_free(session->out_buffer);
  string_free(req);

  leave_function();
  return rc;
}

/**
 * @brief Request a pty with a specific type and size.
 *
 * @param channel       The channel to sent the request.
 *
 * @param terminal      The terminal type ("vt100, xterm,...").
 *
 * @param col           The number of columns.
 *
 * @param row           The number of rows.
 *
 * @return SSH_SUCCESS on success, SSH_ERROR on error.
 */
int channel_request_pty_size(CHANNEL *channel, const char *terminal,
    int col, int row) {
  SSH_SESSION *session = channel->session;
  STRING *term = NULL;
  BUFFER *buffer = NULL;
  int rc = SSH_ERROR;

  enter_function();
#ifdef HAVE_SSH1
  if (channel->version==1) {
    channel_request_pty_size1(channel,terminal, col, row);
    leave_function();
    return rc;
    }
#endif
  buffer = buffer_new();
  if (buffer == NULL) {
    goto error;
  }

  term = string_from_char(terminal);
  if (term == NULL) {
    goto error;
  }

  if (buffer_add_ssh_string(buffer, term) < 0 ||
      buffer_add_u32(buffer, htonl(col)) < 0 ||
      buffer_add_u32(buffer, htonl(row)) < 0 ||
      buffer_add_u32(buffer, 0) < 0 ||
      buffer_add_u32(buffer, 0) < 0 ||
      buffer_add_u32(buffer, htonl(1)) < 0 || /* Add a 0byte string */
      buffer_add_u8(buffer, 0) < 0) {
    goto error;
  }

  rc = channel_request(channel, "pty-req", buffer, 1);
error:
  buffer_free(buffer);
  string_free(term);

  leave_function();
  return rc;
}

/**
 * @brief Request a PTY.
 *
 * @param channel       The channel to send the request.
 *
 * @return SSH_SUCCESS on success, SSH_ERROR on error.
 *
 * @see channel_request_pty_size()
 */
int channel_request_pty(CHANNEL *channel) {
  return channel_request_pty_size(channel, "xterm", 80, 24);
}

/**
 * @brief Change the size of the terminal associated to a channel.
 *
 * @param channel       The channel to change the size.
 *
 * @param cols          The new number of columns.
 *
 * @param rows          The new number of rows.
 *
 * @warning Do not call it from a signal handler if you are not
 * sure any other libssh function using the same channel/session
 * is running at same time (not 100% threadsafe).
 */
int channel_change_pty_size(CHANNEL *channel, int cols, int rows) {
  SSH_SESSION *session = channel->session;
  BUFFER *buffer = NULL;
  int rc = SSH_ERROR;

  enter_function();

#ifdef HAVE_SSH1
  if (channel->version == 1) {
    rc = channel_change_pty_size1(channel,cols,rows);
    leave_function();
    return rc;
  }
#endif

  buffer = buffer_new();
  if (buffer == NULL) {
    goto error;
  }

  if (buffer_add_u32(buffer, htonl(cols)) < 0 ||
      buffer_add_u32(buffer, htonl(rows)) < 0 ||
      buffer_add_u32(buffer, 0) < 0 ||
      buffer_add_u32(buffer, 0) < 0) {
    goto error;
  }

  rc = channel_request(channel, "window-change", buffer, 0);
error:
  buffer_free(buffer);

  leave_function();
  return rc;
}

/**
 * @brief Request a shell.
 *
 * @param channel      The channel to send the request.
 *
 * @returns SSH_SUCCESS on success, SSH_ERROR on error.
 */
int channel_request_shell(CHANNEL *channel) {
#ifdef HAVE_SSH1
  if (channel->version == 1) {
    return channel_request_shell1(channel);
  }
#endif
  return channel_request(channel, "shell", NULL, 1);
}

/**
 * @brief Request a subsystem (for example "sftp").
 *
 * @param channel       The channel to send the request.
 *
 * @param system        The subsystem to request (for example "sftp").
 *
 * @return SSH_SUCCESS on success, SSH_ERROR on error.
 *
 * @warning You normally don't have to call it for sftp, see sftp_new().
 */
int channel_request_subsystem(CHANNEL *channel, const char *sys) {
  BUFFER *buffer = NULL;
  STRING *subsystem = NULL;
  int rc = SSH_ERROR;

  buffer = buffer_new();
  if (buffer == NULL) {
    goto error;
  }

  subsystem = string_from_char(sys);
  if (subsystem == NULL) {
    goto error;
  }

  if (buffer_add_ssh_string(buffer, subsystem) < 0) {
    goto error;
  }

  rc = channel_request(channel, "subsystem", buffer, 1);
error:
  buffer_free(buffer);
  string_free(subsystem);

  return rc;
}

int channel_request_sftp( CHANNEL *channel){
    return channel_request_subsystem(channel, "sftp");
}

/**
 * @brief Set environement variables.
 *
 * @param channel       The channel to set the environement variables.
 *
 * @param name          The name of the variable.
 *
 * @param value         The value to set.
 *
 * @return SSH_SUCCESS on success, SSH_ERROR on error.
 *
 * @warning Some environement variables may be refused by security reasons.
 * */
int channel_request_env(CHANNEL *channel, const char *name, const char *value) {
  BUFFER *buffer = NULL;
  STRING *str = NULL;
  int rc = SSH_ERROR;

  buffer = buffer_new();
  if (buffer == NULL) {
    goto error;
  }

  str = string_from_char(name);
  if (str == NULL) {
    goto error;
  }

  if (buffer_add_ssh_string(buffer, str) < 0) {
    goto error;
  }

  string_free(str);
  str = string_from_char(value);
  if (str == NULL) {
    goto error;
  }

  if (buffer_add_ssh_string(buffer, str) < 0) {
    goto error;
  }

  rc = channel_request(channel, "env", buffer,1);
error:
  buffer_free(buffer);
  string_free(str);

  return rc;
}

/**
 * @brief Run a shell command without an interactive shell.
 *
 * This is similar to 'sh -c command'.
 *
 * @param channel       The channel to execute the command.
 *
 * @param cmd           The command to execute
 *                      (e.g. "ls ~/ -al | grep -i reports").
 *
 * @return SSH_SUCCESS on success, SSH_ERROR on error.
 *
 * @see channel_request_shell()
 */
int channel_request_exec(CHANNEL *channel, const char *cmd) {
  BUFFER *buffer = NULL;
  STRING *command = NULL;
  int rc = SSH_ERROR;

#ifdef HAVE_SSH1
  if (channel->version == 1) {
    return channel_request_exec1(channel, cmd);
  }
#endif

  buffer = buffer_new();
  if (buffer == NULL) {
    goto error;
  }

  command = string_from_char(cmd);
  if (command == NULL) {
    goto error;
  }

  if (buffer_add_ssh_string(buffer, command) < 0) {
    goto error;
  }

  rc = channel_request(channel, "exec", buffer, 1);
error:
  buffer_free(buffer);
  string_free(command);
  return rc;
}

/* TODO : fix the delayed close thing */
/* TODO : fix the blocking behaviours */

/**
 * @brief Read data from a channel into a buffer.
 *
 * @param channel       The channel to read from.
 *
 * @param buffer        The buffer which will get the data.
 *
 * @param count         The count of bytes to be read. If it is biggerthan 0,
 *                      the exact size will be read, else (bytes=0) it will
 *                      return once anything is available.
 *
 * @param is_stderr     A boolean value to mark reading from the stderr stream.
 *
 * @return The number of bytes read, 0 on end of file or SSH_ERROR on error.
 */
int channel_read_buffer(CHANNEL *channel, BUFFER *buffer, u32 count,
    int is_stderr) {
  SSH_SESSION *session=channel->session;
  BUFFER *stdbuf = channel->stdout_buffer;
  u32 maxread = count;
  u32 len;

  buffer_reinit(buffer);

  enter_function();

  if (count == 0) {
    maxread = MAX_PACKET_LEN;
  }

  if (is_stderr) {
    stdbuf = channel->stderr_buffer;
  }

  /*
   * We may have problem if the window is too small to accept as much data
   * as asked
   */
  ssh_log(session, SSH_LOG_PROTOCOL,
      "Read (%d) buffered: %d bytes. Window: %d",
      count,
      buffer_get_rest_len(stdbuf),
      channel->local_window);

  if (count > buffer_get_rest_len(stdbuf) + channel->local_window) {
    if (grow_window(session, channel,
          count - buffer_get_rest_len(stdbuf)) < 0) {
      leave_function();
      return -1;
    }
  }
  /* block reading if asked bytes=0 */
  while (buffer_get_rest_len(stdbuf) == 0 ||
      buffer_get_rest_len(stdbuf) < count) {
    if (channel->remote_eof && buffer_get_rest_len(stdbuf) == 0) {
      leave_function();
      return 0;
    }
    if (channel->remote_eof) {
      /* Return the resting bytes in buffer */
      break;
    }
    if (buffer_get_rest_len(stdbuf) >= maxread) {
      /* Stop reading when buffer is full enough */
      break;
    }

    if ((packet_read(session)) != SSH_OK ||
        (packet_translate(session) != SSH_OK)) {
      leave_function();
      return -1;
    }
    packet_parse(session);
  }

  if(channel->local_window < WINDOWLIMIT) {
    if (grow_window(session, channel, 0) < 0) {
      leave_function();
      return -1;
    }
  }

  if (count == 0) {
    /* write the ful buffer informations */
    if (buffer_add_data(buffer, buffer_get_rest(stdbuf),
          buffer_get_rest_len(stdbuf)) < 0) {
      leave_function();
      return -1;
    }
    buffer_reinit(stdbuf);
  } else {
    /* Read bytes bytes if len is greater, everything otherwise */
    len = buffer_get_rest_len(stdbuf);
    len = (len > count ? count : len);
    if (buffer_add_data(buffer, buffer_get_rest(stdbuf), len) < 0) {
      leave_function();
      return -1;
    }
    buffer_pass_bytes(stdbuf,len);
  }

  leave_function();
  return buffer_get_len(buffer);
}

/* TODO FIXME Fix the delayed close thing */
/* TODO FIXME Fix the blocking behaviours */

/**
 * @brief Reads data from a channel.
 *
 * @param channel       The channel to read from.
 *
 * @param dest          The destination buffer which will get the data.
 *
 * @param count         The count of bytes to be read.
 *
 * @param is_stderr     A boolean value to mark reading from the stderr flow.
 *
 * @return The number of bytes read, 0 on end of file or SSH_ERROR on error.
 *
 * @warning The read function using a buffer has been renamed to
 *          channel_read_buffer().
 */
int channel_read(CHANNEL *channel, void *dest, u32 count, int is_stderr) {
  SSH_SESSION *session = channel->session;
  BUFFER *stdbuf = channel->stdout_buffer;
  u32 len;

  enter_function();

  if (count == 0) {
    leave_function();
    return 0;
  }

  if (is_stderr) {
    stdbuf=channel->stderr_buffer;
  }

  /*
   * We may have problem if the window is too small to accept as much data
   * as asked
   */
  ssh_log(session, SSH_LOG_PROTOCOL,
      "Read (%d) buffered : %d bytes. Window: %d",
      count,
      buffer_get_rest_len(stdbuf),
      channel->local_window);

  if (count > buffer_get_rest_len(stdbuf) + channel->local_window) {
    if (grow_window(session, channel,
          count - buffer_get_rest_len(stdbuf)) < 0) {
      leave_function();
      return -1;
    }
  }

  /* block reading if asked bytes=0 */
  while (buffer_get_rest_len(stdbuf) == 0 ||
      buffer_get_rest_len(stdbuf) < count) {
    if (channel->remote_eof && buffer_get_rest_len(stdbuf) == 0) {
      leave_function();
      return 0;
    }

    if (channel->remote_eof) {
      /* Return the resting bytes in buffer */
      break;
    }

    if (buffer_get_rest_len(stdbuf) >= count) {
      /* Stop reading when buffer is full enough */
      break;
    }

    if ((packet_read(session)) != SSH_OK ||
        (packet_translate(session) != SSH_OK)) {
      leave_function();
      return -1;
    }
    packet_parse(session);
  }

  if (channel->local_window < WINDOWLIMIT) {
    if (grow_window(session, channel, 0) < 0) {
      leave_function();
      return -1;
    }
  }

  len = buffer_get_rest_len(stdbuf);
  /* Read count bytes if len is greater, everything otherwise */
  len = (len > count ? count : len);
  memcpy(dest, buffer_get_rest(stdbuf), len);
  buffer_pass_bytes(stdbuf,len);

  leave_function();
  return len;
}

/**
 * @brief Do a nonblocking read on the channel.
 *
 * A nonblocking read on the specified channel. it will return <= count bytes of
 * data read atomicly.
 *
 * @param channel       The channel to read from.
 *
 * @param dest          A pointer to a destination buffer.
 *
 * @param count         The count of bytes of data to be read.
 *
 * @param is_stderr     A boolean to select the stderr stream.
 *
 * @return The number of bytes read, 0 if nothing is available or
 *         SSH_ERROR on error.
 *
 * @warning Don't forget to check for EOF as it would return 0 here.
 *
 * @see channel_is_eof()
 */
int channel_read_nonblocking(CHANNEL *channel, void *dest, u32 count,
    int is_stderr) {
  SSH_SESSION *session = channel->session;
  u32 to_read;
  int rc;

  enter_function();

  to_read = channel_poll(channel, is_stderr);

  if (to_read <= 0) {
    leave_function();
    return to_read; /* may be an error code */
  }

  if (to_read > count) {
    to_read = count;
  }
  rc = channel_read(channel, dest, to_read, is_stderr);

  leave_function();
  return rc;
}

/**
 * @brief Polls a channel for data to read.
 *
 * @param channel       The channel to poll.
 *
 * @param is_stderr     A boolean to select the stderr stream.
 *
 * @return The number of bytes available for reading, 0 if nothing is available
 *         or SSH_ERROR on error.
 *
 * @warning When the channel is in EOF state, the function returns SSH_EOF.
 *
 * @see channel_is_eof()
 */
int channel_poll(CHANNEL *channel, int is_stderr){
  SSH_SESSION *session = channel->session;
  BUFFER *stdbuf = channel->stdout_buffer;

  enter_function();

  if (is_stderr) {
    stdbuf = channel->stderr_buffer;
  }

  while (buffer_get_rest_len(stdbuf) == 0 && channel->remote_eof == 0) {
    if (ssh_handle_packets(channel->session) <= 0) {
      break;
    }
  }

  if (channel->remote_eof) {
    leave_function();
    return SSH_EOF;
  }

  leave_function();
  return buffer_get_rest_len(stdbuf);
}

/**
 * @brief Recover the session in which belongs a channel.
 *
 * @param channel       The channel to recover the session from.
 *
 * @return The session pointer.
 */
SSH_SESSION *channel_get_session(CHANNEL *channel) {
  return channel->session;
}

/**
 * @brief Get the exit status of the channel (error code from the executed
 *        instruction).
 *
 * @param channel       The channel to get the status from.
 *
 * @return -1 if no exit status has been returned or eof not sent,
 *         the exit status othewise.
 */
int channel_get_exit_status(CHANNEL *channel) {
  if (channel->local_eof == 0) {
    return -1;
  }

  while (channel->remote_eof == 0 || channel->exit_status == -1) {
    /* Parse every incoming packet */
    if (packet_wait(channel->session, 0, 0) != SSH_OK) {
      return -1;
    }
    if (channel->open == 0) {
      return -1;
    }
  }

  return channel->exit_status;
}

/*
 * This function acts as a meta select.
 *
 * First, channels are analyzed to seek potential can-write or can-read ones,
 * then if no channel has been elected, it goes in a loop with the posix
 * select(2).
 * This is made in two parts: protocol select and network select. The protocol
 * select does not use the network functions at all
 */
static int channel_protocol_select(CHANNEL **rchans, CHANNEL **wchans,
    CHANNEL **echans, CHANNEL **rout, CHANNEL **wout, CHANNEL **eout) {
  CHANNEL *chan;
  int i;
  int j = 0;

  for (i = 0; rchans[i] != NULL; i++) {
    chan = rchans[i];

    while (chan->open && ssh_socket_data_available(chan->session->socket)) {
      ssh_handle_packets(chan->session);
    }

    if ((chan->stdout_buffer && buffer_get_len(chan->stdout_buffer) > 0) ||
        (chan->stderr_buffer && buffer_get_len(chan->stderr_buffer) > 0) ||
        chan->remote_eof) {
      rout[j] = chan;
      j++;
    }
  }
  rout[j] = NULL;

  j = 0;
  for(i = 0; wchans[i] != NULL; i++) {
    chan = wchans[i];
    /* It's not our business to seek if the file descriptor is writable */
    if (ssh_socket_data_writable(chan->session->socket) &&
        chan->open && (chan->remote_window > 0)) {
      wout[j] = chan;
      j++;
    }
  }
  wout[j] = NULL;

  j = 0;
  for (i = 0; echans[i] != NULL; i++) {
    chan = echans[i];

    if (!ssh_socket_is_open(chan->session->socket) || !chan->open) {
      eout[j] = chan;
      j++;
    }
  }
  eout[j] = NULL;

  return 0;
}

/* Just count number of pointers in the array */
static int count_ptrs(CHANNEL **ptrs) {
  int c;
  for (c = 0; ptrs[c] != NULL; c++)
    ;

  return c;
}

/**
 * @brief Act like the standard select(2) on channels.
 *
 * The list of pointers are then actualized and will only contain pointers to
 * channels that are respectively readable, writable or have an exception to
 * trap.
 *
 * @param readchans     A NULL pointer or an array of channel pointers,
 *                      terminated by a NULL.
 *
 * @param writechans    A NULL pointer or an array of channel pointers,
 *                      terminated by a NULL.
 *
 * @param exceptchans   A NULL pointer or an array of channel pointers,
 *                      terminated by a NULL.
 *
 * @param timeout       Timeout as defined by select(2).
 *
 * @return SSH_SUCCESS operation successful\n
 *         SSH_EINTR select(2) syscall was interrupted, relaunch the function
 */
int channel_select(CHANNEL **readchans, CHANNEL **writechans,
    CHANNEL **exceptchans, struct timeval * timeout) {
  CHANNEL **rchans, **wchans, **echans;
  CHANNEL *dummy = NULL;
  fd_set rset;
  fd_set wset;
  fd_set eset;
  int fdmax = -1;
  int rc;
  int i;

  /* don't allow NULL pointers */
  if (readchans == NULL) {
    readchans = &dummy;
  }

  if (writechans == NULL) {
    writechans = &dummy;
  }

  if (exceptchans == NULL) {
    exceptchans = &dummy;
  }

  if (readchans[0] == NULL && writechans[0] == NULL && exceptchans[0] == NULL) {
    /* No channel to poll?? Go away! */
    return 0;
  }

  /* Prepare the outgoing temporary arrays */
  rchans = malloc(sizeof(CHANNEL *) * (count_ptrs(readchans) + 1));
  if (rchans == NULL) {
    return SSH_ERROR;
  }

  wchans = malloc(sizeof(CHANNEL *) * (count_ptrs(writechans) + 1));
  if (wchans == NULL) {
    SAFE_FREE(rchans);
    return SSH_ERROR;
  }

  echans = malloc(sizeof(CHANNEL *) * (count_ptrs(exceptchans) + 1));
  if (echans == NULL) {
    SAFE_FREE(rchans);
    SAFE_FREE(wchans);
    return SSH_ERROR;
  }

  /*
   * First, try without doing network stuff then, select and redo the
   * networkless stuff
   */
  do {
    channel_protocol_select(readchans, writechans, exceptchans,
        rchans, wchans, echans);
    if (rchans[0] != NULL || wchans[0] != NULL || echans[0] != NULL) {
      /* We've got one without doing any select overwrite the begining arrays */
      memcpy(readchans, rchans, (count_ptrs(rchans) + 1) * sizeof(CHANNEL *));
      memcpy(writechans, wchans, (count_ptrs(wchans) + 1) * sizeof(CHANNEL *));
      memcpy(exceptchans, echans, (count_ptrs(echans) + 1) * sizeof(CHANNEL *));
      SAFE_FREE(rchans);
      SAFE_FREE(wchans);
      SAFE_FREE(echans);
      return 0;
    }
    /*
     * Since we verified the invalid fd cases into the networkless select,
     * we can be sure all fd are valid ones
     */
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_ZERO(&eset);

    for (i = 0; readchans[i] != NULL; i++) {
      if (!ssh_socket_fd_isset(readchans[i]->session->socket, &rset)) {
        ssh_socket_fd_set(readchans[i]->session->socket, &rset, &fdmax);
      }
    }

    for (i = 0; writechans[i] != NULL; i++) {
      if (!ssh_socket_fd_isset(writechans[i]->session->socket, &wset)) {
        ssh_socket_fd_set(writechans[i]->session->socket, &wset, &fdmax);
      }
    }

    for (i = 0; exceptchans[i] != NULL; i++) {
      if (!ssh_socket_fd_isset(exceptchans[i]->session->socket, &eset)) {
        ssh_socket_fd_set(exceptchans[i]->session->socket, &eset, &fdmax);
      }
    }

    /* Here we go */
    rc = select(fdmax, &rset, &wset, &eset, timeout);
    /* Leave if select was interrupted */
    if (rc == EINTR) {
      SAFE_FREE(rchans);
      SAFE_FREE(wchans);
      SAFE_FREE(echans);
      return SSH_EINTR;
    }

    for (i = 0; readchans[i] != NULL; i++) {
      if (ssh_socket_fd_isset(readchans[i]->session->socket, &rset)) {
        ssh_socket_set_toread(readchans[i]->session->socket);
      }
    }

    for (i = 0; writechans[i] != NULL; i++) {
      if (ssh_socket_fd_isset(writechans[i]->session->socket, &wset)) {
        ssh_socket_set_towrite(writechans[i]->session->socket);
      }
    }

    for (i = 0; exceptchans[i] != NULL; i++) {
      if (ssh_socket_fd_isset(exceptchans[i]->session->socket, &eset)) {
        ssh_socket_set_except(exceptchans[i]->session->socket);
      }
    }
  } while(1); /* Return to do loop */

  /* not reached */
  return 0;
}

/** @} */
/* vim: set ts=2 sw=2 et cindent: */
