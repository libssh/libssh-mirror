/*
 * messages.c - message parsion for the server
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
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

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/server.h"
#include "libssh/ssh2.h"


static SSH_MESSAGE *message_new(SSH_SESSION *session){
  SSH_MESSAGE *msg = malloc(sizeof(SSH_MESSAGE));
  if (msg == NULL) {
    return NULL;
  }

  memset(msg, 0, sizeof(*msg));
  msg->session = session;
  return msg;
}

static SSH_MESSAGE *handle_service_request(SSH_SESSION *session) {
  ssh_string service = NULL;
  char *service_c = NULL;
  SSH_MESSAGE *msg=NULL;

  enter_function();

  service = buffer_get_ssh_string(session->in_buffer);
  if (service == NULL) {
    ssh_set_error(session, SSH_FATAL, "Invalid SSH_MSG_SERVICE_REQUEST packet");
    goto error;
  }

  service_c = string_to_char(service);
  if (service_c == NULL) {
    goto error;
  }
  ssh_log(session, SSH_LOG_PACKET,
        "Received a SERVICE_REQUEST for service %s", service_c);
  msg=message_new(session);
  if(!msg){
    SAFE_FREE(service_c);
    goto error;
  }
  msg->type=SSH_SERVICE_REQUEST;
  msg->service_request.service=service_c;
  error:
  leave_function();
  return msg;
}

static int ssh_message_service_request_reply_default(SSH_MESSAGE *msg) {
  /* The only return code accepted by specifications are success or disconnect */
  return ssh_message_service_reply_success(msg);
}
int ssh_message_service_reply_success(SSH_MESSAGE *msg) {
  struct ssh_string_struct *service;
  SSH_SESSION *session=msg->session;
  if (msg == NULL) {
    return SSH_ERROR;
  }
  ssh_log(session, SSH_LOG_PACKET,
      "Sending a SERVICE_ACCEPT for service %s", msg->service_request.service);
  if (buffer_add_u8(session->out_buffer, SSH2_MSG_SERVICE_ACCEPT) < 0) {
    return -1;
  }
  service=string_from_char(msg->service_request.service);
  if (buffer_add_ssh_string(session->out_buffer, service) < 0) {
    string_free(service);
    return -1;
  }
  string_free(service);
  return packet_send(msg->session);
}

char *ssh_message_service_service(SSH_MESSAGE *msg){
  if (msg == NULL) {
    return NULL;
  }
  return msg->service_request.service;
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
  ssh_string user = NULL;
  ssh_string service = NULL;
  ssh_string method = NULL;
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
  user = NULL;

  service_c = string_to_char(service);
  if (service_c == NULL) {
    goto error;
  }
  method_c = string_to_char(method);
  if (method_c == NULL) {
    goto error;
  }

  string_free(service);
  service = NULL;
  string_free(method);
  method = NULL;

  ssh_log(session, SSH_LOG_PACKET,
      "Auth request for service %s, method %s for user '%s'",
      service_c, method_c,
      msg->auth_request.username);


  if (strcmp(method_c, "none") == 0) {
    msg->auth_request.method = SSH_AUTH_NONE;
    SAFE_FREE(service_c);
    SAFE_FREE(method_c);
    leave_function();
    return msg;
  }

  if (strcmp(method_c, "password") == 0) {
    ssh_string pass = NULL;
    uint8_t tmp;

    msg->auth_request.method = SSH_AUTH_PASSWORD;
    SAFE_FREE(service_c);
    SAFE_FREE(method_c);
    buffer_get_u8(session->in_buffer, &tmp);
    pass = buffer_get_ssh_string(session->in_buffer);
    if (pass == NULL) {
      goto error;
    }
    msg->auth_request.password = string_to_char(pass);
    string_burn(pass);
    string_free(pass);
    pass = NULL;
    if (msg->auth_request.password == NULL) {
      goto error;
    }
    leave_function();
    return msg;
  }

  if (strcmp(method_c, "publickey") == 0) {
    ssh_string algo = NULL;
    ssh_string publickey = NULL;
    uint8_t has_sign;

    msg->auth_request.method = SSH_AUTH_PUBLICKEY;
    SAFE_FREE(method_c);
    buffer_get_u8(session->in_buffer, &has_sign);
    algo = buffer_get_ssh_string(session->in_buffer);
    if (algo == NULL) {
      goto error;
    }
    publickey = buffer_get_ssh_string(session->in_buffer);
    if (publickey == NULL) {
      string_free(algo);
      algo = NULL;
      goto error;
    }
    msg->auth_request.public_key = publickey_from_string(session, publickey);
    string_free(algo);
    algo = NULL;
    string_free(publickey);
    publickey = NULL;
    if (msg->auth_request.public_key == NULL) {
       goto error;
    }
    msg->auth_request.signature_state = 0;
    // has a valid signature ?
    if(has_sign) {
      SIGNATURE *signature = NULL;
      ssh_public_key public_key = msg->auth_request.public_key;
      ssh_string sign = NULL;
      ssh_buffer digest = NULL;

      sign = buffer_get_ssh_string(session->in_buffer);
      if(sign == NULL) {
        ssh_log(session, SSH_LOG_PACKET, "Invalid signature packet from peer");
        msg->auth_request.signature_state = -2;
        goto error;
      }
      signature = signature_from_string(session, sign, public_key,
                                                       public_key->type);
      digest = ssh_userauth_build_digest(session, msg, service_c);
      if(sig_verify(session, public_key, signature,
                            buffer_get(digest), buffer_get_len(digest)) < 0) {
        ssh_log(session, SSH_LOG_PACKET, "Invalid signature from peer");
        msg->auth_request.signature_state = -1;
        string_free(sign);
        sign = NULL;
        goto error;
      }
      else
        ssh_log(session, SSH_LOG_PACKET, "Valid signature received");
      msg->auth_request.signature_state = 1;
    }
    SAFE_FREE(service_c);
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

/* Get the publickey of an auth request */
ssh_public_key ssh_message_auth_publickey(SSH_MESSAGE *msg){
  if (msg == NULL) {
    return NULL;
  }

  return msg->auth_request.public_key;
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
  ssh_string methods = NULL;
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

/* Answer OK to a pubkey auth request */
int ssh_message_auth_reply_pk_ok(SSH_MESSAGE *msg, ssh_string algo, ssh_string pubkey) {
  if (msg == NULL) {
    return SSH_ERROR;
  }

  if (buffer_add_u8(msg->session->out_buffer, SSH2_MSG_USERAUTH_PK_OK) < 0 ||
      buffer_add_ssh_string(msg->session->out_buffer, algo) < 0 ||
      buffer_add_ssh_string(msg->session->out_buffer, pubkey) < 0) {
    return SSH_ERROR;
  }

  return packet_send(msg->session);
}

static SSH_MESSAGE *handle_channel_request_open(SSH_SESSION *session) {
  SSH_MESSAGE *msg = NULL;
  ssh_string type = NULL, originator = NULL, destination = NULL;
  char *type_c = NULL;
  uint32_t sender, window, packet, originator_port, destination_port;

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

  if (strcmp(type_c,"direct-tcpip") == 0) {
    destination = buffer_get_ssh_string(session->in_buffer);
	if (destination == NULL) {
		goto error;
	}
	msg->channel_request_open.destination = string_to_char(type);
	if (msg->channel_request_open.destination == NULL) {
	  string_free(destination);
	  goto error;
	}
    string_free(destination);

    buffer_get_u32(session->in_buffer, &destination_port);
    msg->channel_request_open.destination_port = ntohl(destination_port);

    originator = buffer_get_ssh_string(session->in_buffer);
	if (originator == NULL) {
	  goto error;
	}
	msg->channel_request_open.originator = string_to_char(type);
	if (msg->channel_request_open.originator == NULL) {
	  string_free(originator);
	  goto error;
	}
    string_free(originator);

    buffer_get_u32(session->in_buffer, &originator_port);
    msg->channel_request_open.originator_port = ntohl(originator_port);

    msg->channel_request_open.type = SSH_CHANNEL_DIRECT_TCPIP;
    SAFE_FREE(type_c);
    leave_function();
    return msg;
  }

  if (strcmp(type_c,"forwarded-tcpip") == 0) {
    destination = buffer_get_ssh_string(session->in_buffer);
	if (destination == NULL) {
		goto error;
	}
	msg->channel_request_open.destination = string_to_char(type);
	if (msg->channel_request_open.destination == NULL) {
	  string_free(destination);
	  goto error;
	}
    string_free(destination);

    buffer_get_u32(session->in_buffer, &destination_port);
    msg->channel_request_open.destination_port = ntohl(destination_port);

    originator = buffer_get_ssh_string(session->in_buffer);
	if (originator == NULL) {
	  goto error;
	}
	msg->channel_request_open.originator = string_to_char(type);
	if (msg->channel_request_open.originator == NULL) {
	  string_free(originator);
	  goto error;
	}
    string_free(originator);

    buffer_get_u32(session->in_buffer, &originator_port);
    msg->channel_request_open.originator_port = ntohl(originator_port);

    msg->channel_request_open.type = SSH_CHANNEL_FORWARDED_TCPIP;
    SAFE_FREE(type_c);
    leave_function();
    return msg;
  }

  if (strcmp(type_c,"x11") == 0) {
    originator = buffer_get_ssh_string(session->in_buffer);
	if (originator == NULL) {
	  goto error;
	}
	msg->channel_request_open.originator = string_to_char(type);
	if (msg->channel_request_open.originator == NULL) {
	  string_free(originator);
	  goto error;
	}
    string_free(originator);

    buffer_get_u32(session->in_buffer, &originator_port);
    msg->channel_request_open.originator_port = ntohl(originator_port);

    msg->channel_request_open.type = SSH_CHANNEL_X11;
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

ssh_channel ssh_message_channel_request_open_reply_accept(SSH_MESSAGE *msg) {
  SSH_SESSION *session = msg->session;
  ssh_channel chan = NULL;

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
  ssh_string type = NULL;
  char *type_c = NULL;
  uint32_t channel;
  uint8_t want_reply;

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
    ssh_string term = NULL;
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

  if (strcmp(type_c, "window-change") == 0) {
    SAFE_FREE(type_c);

    msg->channel_request.type = SSH_CHANNEL_REQUEST_WINDOW_CHANGE;

    buffer_get_u32(session->in_buffer, &msg->channel_request.width);
    buffer_get_u32(session->in_buffer, &msg->channel_request.height);
    buffer_get_u32(session->in_buffer, &msg->channel_request.pxwidth);
    buffer_get_u32(session->in_buffer, &msg->channel_request.pxheight);

    msg->channel_request.width = ntohl(msg->channel_request.width);
    msg->channel_request.height = ntohl(msg->channel_request.height);
    msg->channel_request.pxwidth = ntohl(msg->channel_request.pxwidth);
    msg->channel_request.pxheight = ntohl(msg->channel_request.pxheight);

    leave_function();
    return msg;
  }

  if (strcmp(type_c, "subsystem") == 0) {
    ssh_string subsys = NULL;
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
    ssh_string cmd = NULL;

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

  if (strcmp(type_c, "env") == 0) {
    ssh_string name = NULL;
    ssh_string value = NULL;

    SAFE_FREE(type_c);

    name = buffer_get_ssh_string(session->in_buffer);
    if (name == NULL) {
      goto error;
    }
    value = buffer_get_ssh_string(session->in_buffer);
	if (value == NULL) {
		string_free(name);
	  goto error;
	}

    msg->channel_request.type = SSH_CHANNEL_REQUEST_ENV;
    msg->channel_request.var_name = string_to_char(name);
    msg->channel_request.var_value = string_to_char(value);
    if (msg->channel_request.var_name == NULL ||
		msg->channel_request.var_value == NULL) {
      string_free(name);
      string_free(value);
      goto error;
    }
    string_free(name);
    string_free(value);

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

char *ssh_message_channel_request_open_originator(SSH_MESSAGE *msg){
    return msg->channel_request_open.originator;
}

int ssh_message_channel_request_open_originator_port(SSH_MESSAGE *msg){
    return msg->channel_request_open.originator_port;
}

char *ssh_message_channel_request_open_destination(SSH_MESSAGE *msg){
    return msg->channel_request_open.destination;
}

int ssh_message_channel_request_open_destination_port(SSH_MESSAGE *msg){
    return msg->channel_request_open.destination_port;
}

CHANNEL *ssh_message_channel_request_channel(SSH_MESSAGE *msg){
    return msg->channel_request.channel;
}

char *ssh_message_channel_request_pty_term(SSH_MESSAGE *msg){
    return msg->channel_request.TERM;
}

int ssh_message_channel_request_pty_width(SSH_MESSAGE *msg){
    return msg->channel_request.width;
}

int ssh_message_channel_request_pty_height(SSH_MESSAGE *msg){
    return msg->channel_request.height;
}

int ssh_message_channel_request_pty_pxwidth(SSH_MESSAGE *msg){
    return msg->channel_request.pxwidth;
}

int ssh_message_channel_request_pty_pxheight(SSH_MESSAGE *msg){
    return msg->channel_request.pxheight;
}

char *ssh_message_channel_request_env_name(SSH_MESSAGE *msg){
    return msg->channel_request.var_name;
}

char *ssh_message_channel_request_env_value(SSH_MESSAGE *msg){
    return msg->channel_request.var_value;
}

char *ssh_message_channel_request_command(SSH_MESSAGE *msg){
    return msg->channel_request.command;
}

char *ssh_message_channel_request_subsystem(SSH_MESSAGE *msg){
    return msg->channel_request.subsystem;
}

int ssh_message_channel_request_reply_success(SSH_MESSAGE *msg) {
  uint32_t channel;

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
  uint32_t channel;

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

SSH_MESSAGE *ssh_message_retrieve(SSH_SESSION *session, uint32_t packettype){
  SSH_MESSAGE *msg=NULL;
  enter_function();
  switch(packettype) {
    case SSH2_MSG_SERVICE_REQUEST:
      msg=handle_service_request(session);
      break;
    case SSH2_MSG_USERAUTH_REQUEST:
      msg = handle_userauth_request(session);
      break;
    case SSH2_MSG_CHANNEL_OPEN:
      msg = handle_channel_request_open(session);
      break;
    case SSH2_MSG_CHANNEL_REQUEST:
      msg = handle_channel_request(session);
      break;
    default:
      if (handle_unimplemented(session) == 0) {
        ssh_set_error(session, SSH_FATAL,
            "Unhandled message %d\n", session->in_packet.type);
      }
  }
  leave_function();
  return msg;
}

/* \brief blocking message retrieval
 * \bug does anything that is not a message, like a channel read/write
 */
SSH_MESSAGE *ssh_message_get(SSH_SESSION *session) {
  SSH_MESSAGE *msg = NULL;
  enter_function();
  do {
    if ((packet_read(session) != SSH_OK) ||
        (packet_translate(session) != SSH_OK)) {
      leave_function();
      return NULL;
    }
  } while(session->in_packet.type==SSH2_MSG_IGNORE || session->in_packet.type==SSH2_MSG_DEBUG);
  msg=ssh_message_retrieve(session,session->in_packet.type);
  leave_function();
  return msg;
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
    case SSH_SERVICE_REQUEST:
      return ssh_message_service_request_reply_default(msg);
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
  SAFE_FREE(msg);
}

/** \internal
 * \brief handle various SSH request messages and stack them for callback
 * \param session SSH session
 * \param type packet type
 * \returns nothing
 */
void message_handle(SSH_SESSION *session, uint32_t type){
  SSH_MESSAGE *msg=ssh_message_retrieve(session,type);
  if(msg){
    if(!session->ssh_message_list){
      session->ssh_message_list=ssh_list_new();
    }
    ssh_list_add(session->ssh_message_list,msg);
  }
}

/** @brief defines the SSH_MESSAGE callback
 * @param session the current ssh session
 * @param ssh_message_callback a function pointer to a callback taking the
 * current ssh session and received message as parameters. the function returns
 * 0 if the message has been parsed and treated sucessfuly, 1 otherwise (libssh
 * must take care of the response).
 */
void ssh_set_message_callback(SSH_SESSION *session,
    int(*ssh_message_callback)(ssh_session session, struct ssh_message *msg)){
  session->ssh_message_callback=ssh_message_callback;
}

int ssh_execute_message_callbacks(SSH_SESSION *session){
  SSH_MESSAGE *msg=NULL;
  int ret;
  if(!session->ssh_message_list)
    return SSH_OK;
  if(session->ssh_message_callback){
    while((msg=ssh_list_get_head(SSH_MESSAGE *, session->ssh_message_list)) != NULL){
      ret=session->ssh_message_callback(session,msg);
      if(ret==1){
        ret = ssh_message_reply_default(msg);
        if(ret != SSH_OK)
          return ret;
      }
    }
  } else {
    while((msg=ssh_list_get_head(SSH_MESSAGE *, session->ssh_message_list)) != NULL){
      ret = ssh_message_reply_default(msg);
      if(ret != SSH_OK)
        return ret;
    }
  }
  return SSH_OK;
}
/**
 * @}
 */
/* vim: set ts=2 sw=2 et cindent: */
