/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef DH_H_
#define DH_H_

#include "config.h"

#include "libssh/crypto.h"

int ssh_dh_init(void);
void ssh_dh_finalize(void);

int ssh_dh_import_next_pubkey_blob(ssh_session session, ssh_string pubkey_blob);

int ssh_dh_build_k(ssh_session session);
int ssh_client_dh_init(ssh_session session);

ssh_key ssh_dh_get_current_server_publickey(ssh_session session);
int ssh_dh_get_current_server_publickey_blob(ssh_session session,
                                             ssh_string *pubkey_blob);
ssh_key ssh_dh_get_next_server_publickey(ssh_session session);
int ssh_dh_get_next_server_publickey_blob(ssh_session session,
                                          ssh_string *pubkey_blob);

#ifdef WITH_SERVER
void ssh_server_dh_init(ssh_session session);
#endif /* WITH_SERVER */

int ssh_dh_init_common(ssh_session session);
void ssh_dh_cleanup(struct ssh_crypto_struct *crypto);
int ssh_dh_generate_secret(ssh_session session, bignum dest);
int ssh_server_dh_process_init(ssh_session session, ssh_buffer packet);

#endif /* DH_H_ */
