/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

#ifndef PKI_PRIV_H_
#define PKI_PRIV_H_

#define RSA_HEADER_BEGIN "-----BEGIN RSA PRIVATE KEY-----"
#define RSA_HEADER_END "-----END RSA PRIVATE KEY-----"
#define DSA_HEADER_BEGIN "-----BEGIN DSA PRIVATE KEY-----"
#define DSA_HEADER_END "-----END DSA PRIVATE KEY-----"

void ssh_pki_log(const char *format, ...) PRINTF_ATTRIBUTE(1, 2);

/* SSH Key Functions */
ssh_key pki_key_dup(const ssh_key key, int demote);

/* SSH Private Key Functions */
enum ssh_keytypes_e pki_privatekey_type_from_string(const char *privkey);
ssh_key pki_private_key_from_base64(const char *b64_key,
                                    const char *passphrase,
                                    ssh_auth_callback auth_fn,
                                    void *auth_data);

/* SSH Public Key Functions */
int pki_pubkey_build_dss(ssh_key key,
                         ssh_string p,
                         ssh_string q,
                         ssh_string g,
                         ssh_string pubkey);
int pki_pubkey_build_rsa(ssh_key key,
                         ssh_string e,
                         ssh_string n);
ssh_string pki_publickey_to_blob(const ssh_key key);

/* SSH Signature Functions */
ssh_string pki_signature_to_blob(const ssh_signature sign);
ssh_signature pki_signature_from_blob(const ssh_key pubkey,
                                      const ssh_string sig_blob,
                                      enum ssh_keytypes_e type);

/* SSH Signing Functions */
struct signature_struct *pki_do_sign(const ssh_key privatekey,
                                     const unsigned char *hash);
#endif /* PKI_PRIV_H_ */
