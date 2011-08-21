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

#ifndef PKI_H_
#define PKI_H_

#define SSH_KEY_FLAG_EMPTY   0x0
#define SSH_KEY_FLAG_PUBLIC  0x0001
#define SSH_KEY_FLAG_PRIVATE 0x0002

struct ssh_key_struct {
    enum ssh_keytypes_e type;
    int flags;
    const char *type_c; /* Don't free it ! it is static */
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa;
    gcry_sexp_t rsa;
#elif HAVE_LIBCRYPTO
    DSA *dsa;
    RSA *rsa;
    void *ecdsa;
#endif
    void *cert;
};

struct ssh_signature_struct {
    enum ssh_keytypes_e type;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa_sig;
    gcry_sexp_t rsa_sig;
#elif defined HAVE_LIBCRYPTO
    DSA_SIG *dsa_sig;
    ssh_string rsa_sig;
#endif
    void *ecdsa;
};

typedef struct ssh_signature_struct *ssh_signature;

/* SSH Key Functions */
ssh_key ssh_key_dup(const ssh_key key);
void ssh_key_clean (ssh_key key);

/* SSH Signature Functions */
ssh_signature ssh_signature_new(void);
void ssh_signature_free(ssh_signature sign);

int ssh_pki_export_signature_blob(const ssh_signature sign,
                                  ssh_string *sign_blob);
int ssh_pki_import_signature_blob(const ssh_string sig_blob,
                                  const ssh_key pubkey,
                                  ssh_signature *psig);

/* SSH Public Key Functions */
ssh_string ssh_pki_export_pubkey_blob(const ssh_key key);
int ssh_pki_import_pubkey_blob(const ssh_string key_blob,
                               ssh_key *pkey);

/* SSH Private Key Functions */
ssh_key ssh_pki_publickey_from_privatekey(const ssh_key privkey);

/* SSH Signing Functions */
ssh_string ssh_pki_do_sign(ssh_session session, ssh_buffer sigbuf,
    ssh_key privatekey);
ssh_string ssh_pki_do_sign_agent(ssh_session session,
                                 struct ssh_buffer_struct *buf,
                                 const ssh_key pubkey);

/* Temporary functions, to be removed after migration to ssh_key */
ssh_public_key ssh_pki_convert_key_to_publickey(ssh_key key);
ssh_private_key ssh_pki_convert_key_to_privatekey(ssh_key key);

#endif /* PKI_H_ */
