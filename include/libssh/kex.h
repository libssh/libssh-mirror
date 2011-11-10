/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
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

#ifndef KEX_H_
#define KEX_H_

#include "libssh/priv.h"
#include "libssh/callbacks.h"

#define SSH_KEX_METHODS 10

struct ssh_kex_struct {
    unsigned char cookie[16];
    char *methods[SSH_KEX_METHODS];
};

SSH_PACKET_CALLBACK(ssh_packet_kexinit);
#ifdef WITH_SSH1
SSH_PACKET_CALLBACK(ssh_packet_publickey1);
#endif

extern const char *supported_methods[];
extern const char *ssh_kex_nums[];

int ssh_send_kex(ssh_session session, int server_kex);
void ssh_list_kex(ssh_session session, struct ssh_kex_struct *kex);
int set_client_kex(ssh_session session);
int ssh_kex_select_methods(ssh_session session);
int verify_existing_algo(int algo, const char *name);
char **space_tokenize(const char *chain);
int ssh_get_kex1(ssh_session session);
char *ssh_find_matching(const char *in_d, const char *what_d);

#endif /* KEX_H_ */
