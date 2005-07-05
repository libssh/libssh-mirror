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


#endif
