/*
 * messages.c - message parsion for the server
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2005 by Aris Adamantiadis
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

/** \defgroup ssh_messages SSH Messages
 * this file contains the Message parsing utilities for server programs using
 * libssh. The main loop of the program will call ssh_message_get(session) to
 * get messages as they come. they are not 1-1 with the protocol messages.
 * then, the user will know what kind of a message it is and use the appropriate
 * functions to handle it (or use the default handlers if she doesn't know what to
 * do
 * \addtogroup ssh_messages
 * @{
 */

#include <string.h>
#include <stdlib.h>
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/server.h"
#include "libssh/ssh2.h"


static SSH_MESSAGE *message_new(SSH_SESSION *session){
  SSH_MESSAGE *msg = session->ssh_message;

  if (msg == NULL) {
    msg = malloc(sizeof(SSH_MESSAGE));
    if (msg == NULL) {
      return NULL;
    }
    session->ssh_message = msg;
  }
  memset(msg, 0, sizeof(*msg));
  msg->session = session;

  return msg;
}

static int handle_service_request(SSH_SESSION *session) {
  STRING *service = NULL;
  char *service_c = NULL;
  int rc = -1;

  enter_function();

  service = buffer_get_ssh_string(session->in_buffer);
  if (service == NULL) {
    ssh_set_error(session, SSH_FATAL, "Invalid SSH_MSG_SERVICE_REQUEST packet");
    leave_function();
    return -1;
  }

  service_c = string_to_char(service);
  if (service_c == NULL) {
    goto error;
  }

  ssh_log(session, SSH_LOG_PACKET,
      "Sending a SERVICE_ACCEPT for service %s", service_c);
  SAFE_FREE(service_c);

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_SERVICE_ACCEPT) < 0) {
    goto error;
  }
  if (buffer_add_ssh_string(session->out_buffer, service) < 0) {
    goto error;
  }
  if (packet_send(session) != SSH_OK) {
    goto error;
  }

  rc = 0;
error:
  string_free(service);
  leave_function();

  return rc;
}

static int handle_unimplemented(SSH_SESSION *session) {
  if (buffer_add_u32(session->out_buffer, htonl(session->recv_seq - 1)) < 0) {
    return -1;
  }

  if (packet_send(session) != SSH_OK) {
    return -1;
  }

  return 0;
}

static SSH_MESSAGE *handle_userauth_request(SSH_SESSION *session){
  STRING *user = NULL;
  STRING *service = NULL;
  STRING *method = NULL;
  SSH_MESSAGE *msg = NULL;
  char *service_c = NULL;
  char *method_c = NULL;

  enter_function();

  msg = message_new(session);
  if (msg == NULL) {
    return NULL;
  }

  user = buffer_get_ssh_string(session->in_buffer);
  if (user == NULL) {
    goto error;
  }
  service = buffer_get_ssh_string(session->in_buffer);
  if (service == NULL) {
    goto error;
  }
  method = buffer_get_ssh_string(session->in_buffer);
  if (method == NULL) {
    goto error;
  }

  msg->type = SSH_AUTH_REQUEST;
  msg->auth_request.username = string_to_char(user);
  if (msg->auth_request.username == NULL) {
    goto error;
  }
  string_free(user);

  service_c = string_to_char(service);
  if (service_c == NULL) {
    goto error;
  }
  method_c = string_to_char(method);
  if (method_c == NULL) {
    goto error;
  }

  string_free(service);
  string_free(method);

  ssh_log(session, SSH_LOG_PACKET,
      "Auth request for service %s, method %s for user '%s'",
      service_c, method_c,
      msg->auth_request.username);

  SAFE_FREE(service_c);

  if (strcmp(method_c, "none") == 0) {
    msg->auth_request.method = SSH_AUTH_NONE;
    SAFE_FREE(method_c);
    leave_function();
    return msg;
  }

  if (strcmp(method_c, "password") == 0) {
    STRING *pass = NULL;
    u8 tmp;

    msg->auth_request.method = SSH_AUTH_PASSWORD;
    SAFE_FREE(method_c);
    buffer_get_u8(session->in_buffer, &tmp);
    pass = buffer_get_ssh_string(session->in_buffer);
    if (pass == NULL) {
      goto error;
    }
    msg->auth_request.password = string_to_char(pass);
    string_free(pass);
    if (msg->auth_request.password == NULL) {
      goto error;
    }
    leave_function();
    return msg;
  }

  msg->auth_request.method = SSH_AUTH_UNKNOWN;
  SAFE_FREE(method_c);

  leave_function();
  return msg;
error:
  string_free(user);
  string_free(service);
  string_free(method);

  SAFE_FREE(method_c);
  SAFE_FREE(service_c);

  ssh_message_free(msg);

  leave_function();
  return NULL;
}

char *ssh_message_auth_user(SSH_MESSAGE *msg) {
  if (msg == NULL) {
    return NULL;
  }

  return msg->auth_request.username;
}

char *ssh_message_auth_password(SSH_MESSAGE *msg){
  if (msg == NULL) {
    return NULL;
  }

  return msg->auth_request.password;
}

int ssh_message_auth_set_methods(SSH_MESSAGE *msg, int methods) {
  if (msg == NULL || msg->session == NULL) {
    return -1;
  }

  msg->session->auth_methods = methods;

  return 0;
}

static int ssh_message_auth_reply_default(SSH_MESSAGE *msg,int partial) {
  SSH_SESSION *session = msg->session;
  char methods_c[128] = {0};
  STRING *methods = NULL;
  int rc = SSH_ERROR;

  enter_function();

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_FAILURE) < 0) {
    return rc;
  }

  if (session->auth_methods == 0) {
    session->auth_methods = SSH_AUTH_PUBLICKEY | SSH_AUTH_PASSWORD;
  }
  if (session->auth_methods & SSH_AUTH_PUBLICKEY) {
    strcat(methods_c, "publickey,");
  }
  if (session->auth_methods & SSH_AUTH_KEYBINT) {
    strcat(methods_c, "keyboard-interactive,");
  }
  if (session->auth_methods & SSH_AUTH_PASSWORD) {
    strcat(methods_c, "password,");
  }
  if (session->auth_methods & SSH_AUTH_HOSTBASED) {
    strcat(methods_c, "hostbased,");
  }

  /* Strip the comma. */
  methods_c[strlen(methods_c) - 1] = '\0'; // strip the comma. We are sure there is at

  ssh_log(session, SSH_LOG_PACKET,
      "Sending a auth failure. methods that can continue: %s", methods_c);

  methods = string_from_char(methods_c);
  if (methods == NULL) {
    goto error;
  }

  if (buffer_add_ssh_string(msg->session->out_buffer, methods) < 0) {
    goto error;
  }

  if (partial) {
    if (buffer_add_u8(session->out_buffer, 1) < 0) {
      goto error;
    }
  } else {
    if (buffer_add_u8(session->out_buffer, 0) < 0) {
      goto error;
    }
  }

  rc = packet_send(msg->session);
error:
  string_free(methods);

  leave_function();
  return rc;
}

int ssh_message_auth_reply_success(SSH_MESSAGE *msg, int partial) {
  if (msg == NULL) {
    return SSH_ERROR;
  }

  if (partial) {
    return ssh_message_auth_reply_default(msg, partial);
  }

  if (buffer_add_u8(msg->session->out_buffer,SSH2_MSG_USERAUTH_SUCCESS) < 0) {
    return SSH_ERROR;
  }

  return packet_send(msg->session);
}

static SSH_MESSAGE *handle_channel_request_open(SSH_SESSION *session) {
  SSH_MESSAGE *msg = NULL;
  STRING *type = NULL;
  char *type_c = NULL;
  u32 sender, window, packet;

  enter_function();

  msg = message_new(session);
  if (msg == NULL) {
    leave_function();
    return NULL;
  }

  msg->type = SSH_CHANNEL_REQUEST_OPEN;

  type = buffer_get_ssh_string(session->in_buffer);
  if (type == NULL) {
    goto error;
  }
  type_c = string_to_char(type);
  if (type_c == NULL) {
    goto error;
  }

  ssh_log(session, SSH_LOG_PACKET,
      "Clients wants to open a %s channel", type_c);
  string_free(type);

  buffer_get_u32(session->in_buffer, &sender);
  buffer_get_u32(session->in_buffer, &window);
  buffer_get_u32(session->in_buffer, &packet);

  msg->channel_request_open.sender = ntohl(sender);
  msg->channel_request_open.window = ntohl(window);
  msg->channel_request_open.packet_size = ntohl(packet);

  if (strcmp(type_c,"session") == 0) {
    msg->channel_request_open.type = SSH_CHANNEL_SESSION;
    SAFE_FREE(type_c);
    leave_function();
    return msg;
  }

  msg->channel_request_open.type = SSH_CHANNEL_UNKNOWN;
  SAFE_FREE(type_c);

  leave_function();
  return msg;
error:
  string_free(type);
  SAFE_FREE(type_c);
  ssh_message_free(msg);

  leave_function();
  return NULL;
}

CHANNEL *ssh_message_channel_request_open_reply_accept(SSH_MESSAGE *msg) {
  SSH_SESSION *session = msg->session;
  CHANNEL *chan = NULL;

  enter_function();

  if (msg == NULL) {
    leave_function();
    return NULL;
  }

  chan = channel_new(session);
  if (chan == NULL) {
    leave_function();
    return NULL;
  }

  chan->local_channel = ssh_channel_new_id(session);
  chan->local_maxpacket = 35000;
  chan->local_window = 32000;
  chan->remote_channel = msg->channel_request_open.sender;
  chan->remote_maxpacket = msg->channel_request_open.packet_size;
  chan->remote_window = msg->channel_request_open.window;
  chan->open = 1;

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION) < 0) {
    goto error;
  }
  if (buffer_add_u32(session->out_buffer, htonl(chan->remote_channel)) < 0) {
    goto error;
  }
  if (buffer_add_u32(session->out_buffer, htonl(chan->local_channel)) < 0) {
    goto error;
  }
  if (buffer_add_u32(session->out_buffer, htonl(chan->local_window)) < 0) {
    goto error;
  }
  if (buffer_add_u32(session->out_buffer, htonl(chan->local_maxpacket)) < 0) {
    goto error;
  }

  ssh_log(session, SSH_LOG_PACKET,
      "Accepting a channel request_open for chan %d", chan->remote_channel);

  if (packet_send(session) != SSH_OK) {
    goto error;
  }

  leave_function();
  return chan;
error:
  channel_free(chan);

  leave_function();
  return NULL;
}

static int ssh_message_channel_request_open_reply_default(SSH_MESSAGE *msg) {
  ssh_log(msg->session, SSH_LOG_FUNCTIONS, "Refusing a channel");

  if (buffer_add_u8(msg->session->out_buffer
        , SSH2_MSG_CHANNEL_OPEN_FAILURE) < 0) {
    goto error;
  }
  if (buffer_add_u32(msg->session->out_buffer,
        htonl(msg->channel_request_open.sender)) < 0) {
    goto error;
  }
  if (buffer_add_u32(msg->session->out_buffer,
        htonl(SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) < 0) {
    goto error;
  }
  /* reason is an empty string */
  if (buffer_add_u32(msg->session->out_buffer, 0) < 0) {
    goto error;
  }
  /* language too */
  if (buffer_add_u32(msg->session->out_buffer, 0) < 0) {
    goto error;
  }

  return packet_send(msg->session);
error:
  return SSH_ERROR;
}

static SSH_MESSAGE *handle_channel_request(SSH_SESSION *session) {
  SSH_MESSAGE *msg = NULL;
  STRING *type = NULL;
  char *type_c = NULL;
  u32 channel;
  u8 want_reply;

  enter_function();

  msg = message_new(session);
  if (msg == NULL) {
    return NULL;
  }

  buffer_get_u32(session->in_buffer, &channel);
  channel = ntohl(channel);

  type = buffer_get_ssh_string(session->in_buffer);
  if (type == NULL) {
    goto error;
  }
  type_c = string_to_char(type);
  if (type_c == NULL) {
    goto error;
  }
  string_free(type);

  buffer_get_u8(session->in_buffer,&want_reply);

  ssh_log(session, SSH_LOG_PACKET,
      "Received a %s channel_request for channel %d (want_reply=%hhd)",
      type_c, channel, want_reply);

  msg->type = SSH_CHANNEL_REQUEST;
  msg->channel_request.channel = ssh_channel_from_local(session, channel);
  msg->channel_request.want_reply = want_reply;

  if (strcmp(type_c, "pty-req") == 0) {
    STRING *term = NULL;
    char *term_c = NULL;
    SAFE_FREE(type_c);

    term = buffer_get_ssh_string(session->in_buffer);
    if (term == NULL) {
      goto error;
    }
    term_c = string_to_char(term);
    if (term_c == NULL) {
      string_free(term);
      goto error;
    }
    string_free(term);

    msg->channel_request.type = SSH_CHANNEL_REQUEST_PTY;
    msg->channel_request.TERM = term_c;

    buffer_get_u32(session->in_buffer, &msg->channel_request.width);
    buffer_get_u32(session->in_buffer, &msg->channel_request.height);
    buffer_get_u32(session->in_buffer, &msg->channel_request.pxwidth);
    buffer_get_u32(session->in_buffer, &msg->channel_request.pxheight);

    msg->channel_request.width = ntohl(msg->channel_request.width);
    msg->channel_request.height = ntohl(msg->channel_request.height);
    msg->channel_request.pxwidth = ntohl(msg->channel_request.pxwidth);
    msg->channel_request.pxheight = ntohl(msg->channel_request.pxheight);
    msg->channel_request.modes = buffer_get_ssh_string(session->in_buffer);
    if (msg->channel_request.modes == NULL) {
      SAFE_FREE(term_c);
      goto error;
    }

    leave_function();
    return msg;
  }

  if (strcmp(type_c, "subsystem") == 0) {
    STRING *subsys = NULL;
    char *subsys_c = NULL;

    SAFE_FREE(type_c);

    subsys = buffer_get_ssh_string(session->in_buffer);
    if (subsys == NULL) {
      goto error;
    }
    subsys_c = string_to_char(subsys);
    if (subsys_c == NULL) {
      string_free(subsys);
      goto error;
    }
    string_free(subsys);

    msg->channel_request.type = SSH_CHANNEL_REQUEST_SUBSYSTEM;
    msg->channel_request.subsystem = subsys_c;

    leave_function();
    return msg;
  }

  if (strcmp(type_c, "shell") == 0) {
    SAFE_FREE(type_c);
    msg->channel_request.type = SSH_CHANNEL_REQUEST_SHELL;

    leave_function();
    return msg;
  }
  if (strcmp(type_c, "exec") == 0) {
    STRING *cmd = NULL;

    SAFE_FREE(type_c);

    cmd = buffer_get_ssh_string(session->in_buffer);
    if (cmd == NULL) {
      goto error;
    }

    msg->channel_request.type = SSH_CHANNEL_REQUEST_EXEC;
    msg->channel_request.command = string_to_char(cmd);
    if (msg->channel_request.command == NULL) {
      string_free(cmd);
      goto error;
    }
    string_free(cmd);

    leave_function();
    return msg;
  }

  msg->channel_request.type = SSH_CHANNEL_UNKNOWN;
  SAFE_FREE(type_c);

  leave_function();
  return msg;
error:
  string_free(type);
  SAFE_FREE(type_c);
  ssh_message_free(msg);

  leave_function();
  return NULL;
}

char *ssh_message_channel_request_subsystem(SSH_MESSAGE *msg){
    return msg->channel_request.subsystem;
}

int ssh_message_channel_request_reply_success(SSH_MESSAGE *msg) {
  u32 channel;

  if (msg == NULL) {
    return SSH_ERROR;
  }

  if (msg->channel_request.want_reply) {
    channel = msg->channel_request.channel->remote_channel;

    ssh_log(msg->session, SSH_LOG_PACKET,
        "Sending a channel_request success to channel %d", channel);

    if (buffer_add_u8(msg->session->out_buffer, SSH2_MSG_CHANNEL_SUCCESS) < 0) {
      return SSH_ERROR;
    }
    if (buffer_add_u32(msg->session->out_buffer, htonl(channel)) < 0) {
      return SSH_ERROR;
    }

    return packet_send(msg->session);
  }

  ssh_log(msg->session, SSH_LOG_PACKET,
      "The client doesn't want to know the request succeeded");

  return SSH_OK;
}

static int ssh_message_channel_request_reply_default(SSH_MESSAGE *msg) {
  u32 channel;

  if (msg->channel_request.want_reply) {
    channel = msg->channel_request.channel->remote_channel;

    ssh_log(msg->session, SSH_LOG_PACKET,
        "Sending a default channel_request denied to channel %d", channel);

    if (buffer_add_u8(msg->session->out_buffer, SSH2_MSG_CHANNEL_FAILURE) < 0) {
      return SSH_ERROR;
    }
    if (buffer_add_u32(msg->session->out_buffer, htonl(channel)) < 0) {
      return SSH_ERROR;
    }

    return packet_send(msg->session);
  }

  ssh_log(msg->session, SSH_LOG_PACKET,
      "The client doesn't want to know the request failed!");

  return SSH_OK;
}

SSH_MESSAGE *ssh_message_get(SSH_SESSION *session) {
  SSH_MESSAGE *msg = NULL;

  enter_function();

  do {
    if ((packet_read(session) != SSH_OK) ||
        (packet_translate(session) != SSH_OK)) {
      goto error;
    }
    switch(session->in_packet.type) {
      case SSH2_MSG_SERVICE_REQUEST:
        if (handle_service_request(session) < 0) {
          goto error;
        }
        break;
      case SSH2_MSG_IGNORE:
      case SSH2_MSG_DEBUG:
        break;
      case SSH2_MSG_USERAUTH_REQUEST:
        msg = handle_userauth_request(session);

        leave_function();
        return msg;
      case SSH2_MSG_CHANNEL_OPEN:
        msg = handle_channel_request_open(session);

        leave_function();
        return msg;
      case SSH2_MSG_CHANNEL_REQUEST:
        msg = handle_channel_request(session);
        leave_function();

        return msg;
      default:
        if (handle_unimplemented(session) == 0) {
          ssh_set_error(session, SSH_FATAL,
              "Unhandled message %d\n", session->in_packet.type);
        }
        goto error;
    }
  } while(1);

error:
  leave_function();
  return NULL;
}

int ssh_message_type(SSH_MESSAGE *msg) {
  if (msg == NULL) {
    return -1;
  }

  return msg->type;
}

int ssh_message_subtype(SSH_MESSAGE *msg) {
  if (msg == NULL) {
    return -1;
  }

  switch(msg->type) {
    case SSH_AUTH_REQUEST:
      return msg->auth_request.method;
    case SSH_CHANNEL_REQUEST_OPEN:
      return msg->channel_request_open.type;
    case SSH_CHANNEL_REQUEST:
      return msg->channel_request.type;
  }

  return -1;
}

int ssh_message_reply_default(SSH_MESSAGE *msg) {
  if (msg == NULL) {
    return -1;
  }

  switch(msg->type) {
    case SSH_AUTH_REQUEST:
      return ssh_message_auth_reply_default(msg, 0);
    case SSH_CHANNEL_REQUEST_OPEN:
      return ssh_message_channel_request_open_reply_default(msg);
    case SSH_CHANNEL_REQUEST:
      return ssh_message_channel_request_reply_default(msg);
    default:
      ssh_log(msg->session, SSH_LOG_PACKET,
          "Don't know what to default reply to %d type",
          msg->type);
      break;
  }

  return -1;
}

void ssh_message_free(SSH_MESSAGE *msg){
  if (msg == NULL) {
    return;
  }

  switch(msg->type) {
    case SSH_AUTH_REQUEST:
      SAFE_FREE(msg->auth_request.username);
      if (msg->auth_request.password) {
        memset(msg->auth_request.password, 0,
            strlen(msg->auth_request.password));
        SAFE_FREE(msg->auth_request.password);
      }
      break;
    case SSH_CHANNEL_REQUEST_OPEN:
      SAFE_FREE(msg->channel_request_open.originator);
      SAFE_FREE(msg->channel_request_open.destination);
      break;
    case SSH_CHANNEL_REQUEST:
      SAFE_FREE(msg->channel_request.TERM);
      SAFE_FREE(msg->channel_request.modes);
      SAFE_FREE(msg->channel_request.var_name);
      SAFE_FREE(msg->channel_request.var_value);
      SAFE_FREE(msg->channel_request.command);
      SAFE_FREE(msg->channel_request.subsystem);
      break;
  }
  ZERO_STRUCTP(msg);
}

/**
 * @}
 */
/* vim: set ts=2 sw=2 et cindent: */
