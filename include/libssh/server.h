/*
Copyright 2004 Aris Adamantiadis

This file is part of the SSH Library

The SSH Library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or (at your
option) any later version.

The SSH Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.

You should have received a copy of the GNU Lesser General Public License
along with the SSH Library; see the file COPYING.  If not, write to
the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
MA 02111-1307, USA. */

#ifndef SERVER_H
#define SERVER_H

#include "libssh/libssh.h"
#include "libssh/priv.h"
#define SERVERBANNER CLIENTBANNER

struct ssh_bind_struct {
    struct error_struct error;
    int bindfd;
    SSH_OPTIONS *options;
    int blocking;
    int toaccept;
};

typedef struct ssh_bind_struct SSH_BIND;

SSH_BIND *ssh_bind_new();
void ssh_bind_set_options(SSH_BIND *ssh_bind, SSH_OPTIONS *options);
int ssh_bind_listen(SSH_BIND *ssh_bind);
void ssh_bind_set_blocking(SSH_BIND *ssh_bind,int blocking);
int ssh_bind_get_fd(SSH_BIND *ssh_bind);
int ssh_bind_set_toaccept(SSH_BIND *ssh_bind);
SSH_SESSION *ssh_bind_accept(SSH_BIND *ssh_bind);
void ssh_bind_free(SSH_BIND *ssh_bind);
int ssh_accept(SSH_SESSION *session);

/* messages.c */

#define SSH_AUTH_REQUEST 1
#define SSH_CHANNEL_REQUEST_OPEN 2
#define SSH_CHANNEL_REQUEST 3

#define SSH_AUTH_NONE (1<<0)
#define SSH_AUTH_PASSWORD (1<<1)
#define SSH_AUTH_HOSTBASED (1<<2)
#define SSH_AUTH_PUBLICKEY (1<<3)
#define SSH_AUTH_KEYBINT (1<<4)
#define SSH_AUTH_UNKNOWN 0

struct ssh_auth_request {
    char *username;
    int method;
    char *password;
};


#define SSH_CHANNEL_SESSION 1
#define SSH_CHANNEL_TCPIP 2
#define SSH_CHANNEL_X11 3
#define SSH_CHANNEL_UNKNOWN 4
struct ssh_channel_request_open {
    int type;
    u32 sender;
    u32 window;
    u32 packet_size;
    char *originator;
    u16 orignator_port;
    char *destination;
    u16 destination_port;
};

#define SSH_CHANNEL_REQUEST_PTY 1
#define SSH_CHANNEL_REQUEST_EXEC 2
#define SSH_CHANNEL_REQUEST_SHELL 3
#define SSH_CHANNEL_REQUEST_ENV 4
#define SSH_CHANNEL_REQUEST_SUBSYSTEM 5
#define SSH_CHANNEL_REQUEST_WINDOW_CHANGE 6
#define SSH_CHANNEL_REQUEST_UNKNOWN 7

struct ssh_channel_request {
    int type;
    CHANNEL *channel;
    u8 want_reply;
    /* pty-req type specifics */
    char *TERM;
    u32 width;
    u32 height;
    u32 pxwidth;
    u32 pxheight;
    STRING *modes;
    
    /* env type request */
    char *var_name;
    char *var_value;
    /* exec type request */
    char *command;
    /* subsystem */
    char *subsystem;
};

struct ssh_message {
    SSH_SESSION *session;
    int type;
    struct ssh_auth_request auth_request;
    struct ssh_channel_request_open channel_request_open;
    struct ssh_channel_request channel_request;
};

typedef struct ssh_message SSH_MESSAGE;

SSH_MESSAGE *ssh_message_get(SSH_SESSION *session);
int ssh_message_type(SSH_MESSAGE *msg);
int ssh_message_subtype(SSH_MESSAGE *msg);
int ssh_message_reply_default(SSH_MESSAGE *msg);
void ssh_message_free(SSH_MESSAGE *msg);

char *ssh_message_auth_user(SSH_MESSAGE *msg);
char *ssh_message_auth_password(SSH_MESSAGE *msg);
int ssh_message_auth_reply_success(SSH_MESSAGE *msg,int partial);
void ssh_message_auth_set_methods(SSH_MESSAGE *msg, int methods);

CHANNEL *ssh_message_channel_request_open_reply_accept(SSH_MESSAGE *msg);

CHANNEL *ssh_message_channel_request_channel(SSH_MESSAGE *msg);
// returns the TERM env variable
char *ssh_message_channel_request_pty_term(SSH_MESSAGE *msg);
char *ssh_message_channel_request_subsystem(SSH_MESSAGE *msg);
int ssh_message_channel_request_reply_success(SSH_MESSAGE *msg);

#endif
