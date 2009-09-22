/*
 * server.c - functions for creating a SSH server
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2004-2005 by Aris Adamantiadis
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

/**
 * \defgroup ssh_server SSH Server
 * \addtogroup ssh_server
 * @{
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libssh/priv.h"
#include "libssh/libssh.h"
#include "libssh/server.h"
#include "libssh/ssh2.h"

#ifdef _WIN32

#include <winsock2.h>
#define SOCKOPT_TYPE_ARG4 char

/* We need to provide hstrerror. Not we can't call the parameter h_errno because it's #defined */
static char *hstrerror(int h_errno_val) {
  static char text[50] = {0};

  snprintf(text, sizeof(text), "gethostbyname error %d\n", h_errno_val);

  return text;
}
#else /* _WIN32 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#define SOCKOPT_TYPE_ARG4 int

#endif /* _WIN32 */

/* TODO FIXME: must use getaddrinfo */
static socket_t bind_socket(SSH_BIND *ssh_bind, const char *hostname,
    int port) {
  struct sockaddr_in myaddr;
  struct hostent *hp=NULL;
  socket_t s;
  int opt = 1;

  s = socket(PF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    ssh_set_error(ssh_bind, SSH_FATAL, "%s", strerror(errno));
    return -1;
  }

#ifdef HAVE_GETHOSTBYNAME
  hp = gethostbyname(hostname);
#endif

  if (hp == NULL) {
    ssh_set_error(ssh_bind, SSH_FATAL,
        "Resolving %s: %s", hostname, hstrerror(h_errno));
    close(s);
    return -1;
  }

  memset(&myaddr, 0, sizeof(myaddr));
  memcpy(&myaddr.sin_addr, hp->h_addr, hp->h_length);
  myaddr.sin_family = hp->h_addrtype;
  myaddr.sin_port = htons(port);

  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
    ssh_set_error(ssh_bind, SSH_FATAL,
        "Setting socket options failed: %s", hstrerror(h_errno));
    close(s);
    return -1;
  }

  if (bind(s, (struct sockaddr *) &myaddr, sizeof(myaddr)) < 0) {
    ssh_set_error(ssh_bind, SSH_FATAL, "Binding to %s:%d: %s",
        hostname,
        port,
        strerror(errno));
    close(s);
    return -1;
  }

  return s;
}

SSH_BIND *ssh_bind_new(void) {
  SSH_BIND *ptr;

  ptr = malloc(sizeof(SSH_BIND));
  if (ptr == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(ptr);
  ptr->bindfd = -1;

  return ptr;
}

void ssh_bind_set_options(SSH_BIND *ssh_bind, SSH_OPTIONS *options) {
  ssh_bind->options = options;
}

int ssh_bind_listen(SSH_BIND *ssh_bind) {
  const char *host;
  int fd;

  if (ssh_bind->options == NULL) {
    return -1;
  }

  if (ssh_init() < 0) {
    return -1;
  }

  host = ssh_bind->options->bindaddr;
  if (host == NULL) {
    host = "0.0.0.0";
  }

  fd = bind_socket(ssh_bind, host, ssh_bind->options->bindport);
  if (fd < 0) {
    return -1;
  }
  ssh_bind->bindfd = fd;

  if (listen(fd, 10) < 0) {
    ssh_set_error(ssh_bind, SSH_FATAL,
        "Listening to socket %d: %s",
        fd, strerror(errno));
    close(fd);
    return -1;
  }

  return 0;
}

void ssh_bind_set_blocking(SSH_BIND *ssh_bind, int blocking) {
  ssh_bind->blocking = blocking ? 1 : 0;
}

socket_t ssh_bind_get_fd(SSH_BIND *ssh_bind) {
  return ssh_bind->bindfd;
}

void ssh_bind_set_fd(SSH_BIND *ssh_bind, socket_t fd) {
  ssh_bind->bindfd = fd;
}

void ssh_bind_fd_toaccept(SSH_BIND *ssh_bind) {
  ssh_bind->toaccept = 1;
}

SSH_SESSION *ssh_bind_accept(SSH_BIND *ssh_bind) {
  SSH_SESSION *session;
  ssh_private_key dsa = NULL;
  ssh_private_key rsa = NULL;
  int fd = -1;

  if (ssh_bind->bindfd < 0) {
    ssh_set_error(ssh_bind, SSH_FATAL,
        "Can't accept new clients on a not bound socket.");
    return NULL;
  }

  if (ssh_bind->options->dsakey == NULL || ssh_bind->options->rsakey == NULL) {
    ssh_set_error(ssh_bind, SSH_FATAL,
        "DSA or RSA host key file must be set before accept()");
    return NULL;
  }

  if (ssh_bind->options->dsakey) {
    dsa = _privatekey_from_file(ssh_bind, ssh_bind->options->dsakey, TYPE_DSS);
    if (dsa == NULL) {
      return NULL;
    }
  }

  if (ssh_bind->options->rsakey) {
    rsa = _privatekey_from_file(ssh_bind, ssh_bind->options->rsakey, TYPE_RSA);
    if (rsa == NULL) {
      privatekey_free(dsa);
      return NULL;
    }
  }

  fd = accept(ssh_bind->bindfd, NULL, NULL);
  if (fd < 0) {
    ssh_set_error(ssh_bind, SSH_FATAL,
        "Accepting a new connection: %s",
        strerror(errno));
    privatekey_free(dsa);
    privatekey_free(rsa);
    return NULL;
  }

  session = ssh_new();
  if (session == NULL) {
    ssh_set_error(ssh_bind, SSH_FATAL, "Not enough space");
    privatekey_free(dsa);
    privatekey_free(rsa);
    return NULL;
  }
  session->server = 1;
  session->version = 2;
  session->options = ssh_options_copy(ssh_bind->options);
  if (session->options == NULL) {
    ssh_set_error(ssh_bind, SSH_FATAL, "No space left");
    privatekey_free(dsa);
    privatekey_free(rsa);
    ssh_cleanup(session);
    return NULL;
  }

  ssh_socket_free(session->socket);
  session->socket = ssh_socket_new(session);
  if (session->socket == NULL) {
    privatekey_free(dsa);
    privatekey_free(rsa);
    ssh_cleanup(session);
    return NULL;
  }
  ssh_socket_set_fd(session->socket,fd);
  session->dsa_key = dsa;
  session->rsa_key = rsa;

  return session;
}

void ssh_bind_free(SSH_BIND *ssh_bind){
  if (ssh_bind == NULL) {
    return;
  }

  if (ssh_bind->bindfd >= 0) {
    close(ssh_bind->bindfd);
  }
  ssh_bind->bindfd = -1;
  if (ssh_bind->options) {
    ssh_options_free(ssh_bind->options);
  }
  SAFE_FREE(ssh_bind);
}

extern char *supported_methods[];

static int server_set_kex(SSH_SESSION * session) {
  KEX *server = &session->server_kex;
  SSH_OPTIONS *options = session->options;
  int i, j;
  char *wanted;

  ZERO_STRUCTP(server);
  /*
   * The program might ask for a specific cookie to be sent. Useful for server
   * debugging
   */
  if (options->wanted_cookie) {
    memcpy(server->cookie, options->wanted_cookie, 16);
  } else {
    ssh_get_random(server->cookie, 16, 0);
  }

  if (session->dsa_key != NULL && session->rsa_key != NULL) {
    if (ssh_options_set(options, SSH_OPTIONS_SERVER_HOSTKEY,
          "ssh-dss,ssh-rsa") < 0) {
      return -1;
    }
  } else if (session->dsa_key != NULL) {
    if (ssh_options_set(options, SSH_OPTIONS_SERVER_HOSTKEY, "ssh-dss") < 0) {
      return -1;
    }
  } else {
    if (ssh_options_set(options, SSH_OPTIONS_SERVER_HOSTKEY, "ssh-rsa") < 0) {
      return -1;
    }
  }

  server->methods = malloc(10 * sizeof(char **));
  if (server->methods == NULL) {
    return -1;
  }

  for (i = 0; i < 10; i++) {
    if ((wanted = options->wanted_methods[i]) == NULL) {
      wanted = supported_methods[i];
    }
    server->methods[i] = strdup(wanted);
    if (server->methods[i] == NULL) {
      for (j = i - 1; j <= 0; j--) {
        SAFE_FREE(server->methods[j]);
      }
      SAFE_FREE(server->methods);
      return -1;
    }
  }

  return 0;
}

static int dh_handshake_server(SSH_SESSION *session) {
  ssh_string e;
  ssh_string f;
  ssh_string pubkey;
  ssh_string sign;
  ssh_public_key pub;
  ssh_private_key prv;

  if (packet_wait(session, SSH2_MSG_KEXDH_INIT, 1) != SSH_OK) {
    return -1;
  }

  e = buffer_get_ssh_string(session->in_buffer);
  if (e == NULL) {
    ssh_set_error(session, SSH_FATAL, "No e number in client request");
    return -1;
  }
  if (dh_import_e(session, e) < 0) {
    ssh_set_error(session, SSH_FATAL, "Cannot import e number");
    string_free(e);
    return -1;
  }
  string_free(e);

  if (dh_generate_y(session) < 0) {
    ssh_set_error(session, SSH_FATAL, "Could not create y number");
    return -1;
  }
  if (dh_generate_f(session) < 0) {
    ssh_set_error(session, SSH_FATAL, "Could not create f number");
    return -1;
  }

  f = dh_get_f(session);
  if (f == NULL) {
    ssh_set_error(session, SSH_FATAL, "Could not get the f number");
    return -1;
  }

  switch(session->hostkeys){
    case TYPE_DSS:
      prv = session->dsa_key;
      break;
    case TYPE_RSA:
      prv = session->rsa_key;
      break;
    default:
      prv = NULL;
  }

  pub = publickey_from_privatekey(prv);
  if (pub == NULL) {
    ssh_set_error(session, SSH_FATAL,
        "Could not get the public key from the private key");
    string_free(f);
    return -1;
  }
  pubkey = publickey_to_string(pub);
  publickey_free(pub);
  if (pubkey == NULL) {
    ssh_set_error(session, SSH_FATAL, "Not enough space");
    string_free(f);
    return -1;
  }

  dh_import_pubkey(session, pubkey);
  if (dh_build_k(session) < 0) {
    ssh_set_error(session, SSH_FATAL, "Could not import the public key");
    string_free(f);
    return -1;
  }

  if (make_sessionid(session) != SSH_OK) {
    ssh_set_error(session, SSH_FATAL, "Could not create a session id");
    string_free(f);
    return -1;
  }

  sign = ssh_sign_session_id(session, prv);
  if (sign == NULL) {
    ssh_set_error(session, SSH_FATAL, "Could not sign the session id");
    string_free(f);
    return -1;
  }

  /* Free private keys as they should not be readable after this point */
  if (session->rsa_key) {
    privatekey_free(session->rsa_key);
    session->rsa_key = NULL;
  }
  if (session->dsa_key) {
    privatekey_free(session->dsa_key);
    session->dsa_key = NULL;
  }

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_KEXDH_REPLY) < 0 ||
      buffer_add_ssh_string(session->out_buffer, pubkey) < 0 ||
      buffer_add_ssh_string(session->out_buffer, f) < 0 ||
      buffer_add_ssh_string(session->out_buffer, sign) < 0) {
    ssh_set_error(session, SSH_FATAL, "Not enough space");
    buffer_reinit(session->out_buffer);
    string_free(f);
    string_free(sign);
    return -1;
  }
  string_free(f);
  string_free(sign);

  if (packet_send(session) != SSH_OK) {
    return -1;
  }

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS) < 0) {
    buffer_reinit(session->out_buffer);
    return -1;
  }

  if (packet_send(session) != SSH_OK) {
    return -1;
  }
  ssh_log(session, SSH_LOG_PACKET, "SSH_MSG_NEWKEYS sent");

  if (packet_wait(session, SSH2_MSG_NEWKEYS, 1) != SSH_OK) {
    return -1;
  }
  ssh_log(session, SSH_LOG_PACKET, "Got SSH_MSG_NEWKEYS");

  if (generate_session_keys(session) < 0) {
    return -1;
  }

  /*
   * Once we got SSH2_MSG_NEWKEYS we can switch next_crypto and
   * current_crypto
   */
  if (session->current_crypto) {
    crypto_free(session->current_crypto);
  }

  /* FIXME TODO later, include a function to change keys */
  session->current_crypto = session->next_crypto;
  session->next_crypto = crypto_new();
  if (session->next_crypto == NULL) {
    return -1;
  }

  return 0;
}

/* Do the banner and key exchange */
int ssh_accept(SSH_SESSION *session) {
  if (ssh_send_banner(session, 1) < 0) {
    return -1;
  }

  session->alive = 1;

  session->clientbanner = ssh_get_banner(session);
  if (session->clientbanner == NULL) {
    return -1;
  }

  if (server_set_kex(session) < 0) {
    return -1;
  }

  if (ssh_send_kex(session, 1) < 0) {
    return -1;
  }

  if (ssh_get_kex(session,1) < 0) {
    return -1;
  }

  ssh_list_kex(session, &session->client_kex);
  crypt_set_algorithms_server(session);

  if (dh_handshake_server(session) < 0) {
    return -1;
  }

  session->connected = 1;

  return 0;
}

/**
 * @brief Blocking write on channel for stderr.
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
int channel_write_stderr(ssh_channel channel, const void *data, uint32_t len) {
  return channel_write_common(channel, data, len, 1);
}

/* messages */

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
    session->auth_methods = SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_PASSWORD;
  }
  if (session->auth_methods & SSH_AUTH_METHOD_PUBLICKEY) {
    strcat(methods_c, "publickey,");
  }
  if (session->auth_methods & SSH_AUTH_METHOD_INTERACTIVE) {
    strcat(methods_c, "keyboard-interactive,");
  }
  if (session->auth_methods & SSH_AUTH_METHOD_PASSWORD) {
    strcat(methods_c, "password,");
  }
  if (session->auth_methods & SSH_AUTH_METHOD_HOSTBASED) {
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

int ssh_message_reply_default(SSH_MESSAGE *msg) {
  if (msg == NULL) {
    return -1;
  }

  switch(msg->type) {
    case SSH_REQUEST_AUTH:
      return ssh_message_auth_reply_default(msg, 0);
    case SSH_REQUEST_CHANNEL_OPEN:
      return ssh_message_channel_request_open_reply_default(msg);
    case SSH_REQUEST_CHANNEL:
      return ssh_message_channel_request_reply_default(msg);
    case SSH_REQUEST_SERVICE:
      return ssh_message_service_request_reply_default(msg);
    default:
      ssh_log(msg->session, SSH_LOG_PACKET,
          "Don't know what to default reply to %d type",
          msg->type);
      break;
  }

  return -1;
}

char *ssh_message_service_service(SSH_MESSAGE *msg){
  if (msg == NULL) {
    return NULL;
  }
  return msg->service_request.service;
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

ssh_channel ssh_message_channel_request_channel(SSH_MESSAGE *msg){
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

/** @brief defines the SSH_MESSAGE callback
 * @param session the current ssh session
 * @param ssh_message_callback a function pointer to a callback taking the
 * current ssh session and received message as parameters. the function returns
 * 0 if the message has been parsed and treated sucessfuly, 1 otherwise (libssh
 * must take care of the response).
 */
void ssh_set_message_callback(SSH_SESSION *session,
    int(*ssh_message_callback)(ssh_session session, ssh_message msg)){
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
/** @}
 */
/* vim: set ts=2 sw=2 et cindent: */
