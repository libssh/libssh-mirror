/*
 * pki_crypto.c - PKI infrastructure using OpenSSL
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 * Copyright (c) 2009-2011 by Andreas Schneider <asn@cryptomilk.org>
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

#ifndef _PKI_CRYPTO_H
#define _PKI_CRYPTO_H

#include "config.h"

#include <openssl/pem.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "libssh/priv.h"
#include "libssh/libssh.h"
#include "libssh/session.h"
#include "libssh/callbacks.h"
#include "libssh/pki.h"

static int pem_get_password(char *buf, int size, int rwflag, void *userdata) {
    ssh_session session = userdata;

    (void) rwflag; /* unused */

    if (buf == NULL) {
        return 0;
    }

    ssh_log(session, SSH_LOG_RARE,
            "Trying to call external authentication function");

    memset(buf, '\0', size);
    if (session &&
        session->common.callbacks &&
        session->common.callbacks->auth_function) {
        int rc;

        rc = session->common.callbacks->auth_function("Passphrase for private key:",
                                                      buf, size, 0, 0,
                                                      session->common.callbacks->userdata);
        if (rc == 0) {
            return strlen(buf);
        }
    }

    return 0;
}

ssh_key pki_private_key_from_base64(ssh_session session,
                                    const char *b64_key,
                                    const char *passphrase) {
    BIO *mem = NULL;
    DSA *dsa = NULL;
    RSA *rsa = NULL;
    ssh_key key;
    enum ssh_keytypes_e type;

    /* needed for openssl initialization */
    if (ssh_init() < 0) {
        return NULL;
    }

    type = pki_privatekey_type_from_string(b64_key);
    if (type == SSH_KEYTYPE_UNKNOWN) {
        ssh_set_error(session, SSH_FATAL, "Unknown or invalid private key.");
        return NULL;
    }

    mem = BIO_new_mem_buf((void*)b64_key, -1);

    switch (type) {
        case SSH_KEYTYPE_DSS:
            if (passphrase == NULL) {
                if (session->common.callbacks && session->common.callbacks->auth_function) {
                    dsa = PEM_read_bio_DSAPrivateKey(mem, NULL, pem_get_password, session);
                } else {
                    /* openssl uses its own callback to get the passphrase here */
                    dsa = PEM_read_bio_DSAPrivateKey(mem, NULL, NULL, NULL);
                }
            } else {
                dsa = PEM_read_bio_DSAPrivateKey(mem, NULL, NULL, (void *) passphrase);
            }

            BIO_free(mem);

            if (dsa == NULL) {
                ssh_set_error(session, SSH_FATAL,
                              "Parsing private key: %s",
                              ERR_error_string(ERR_get_error(), NULL));
                return NULL;
            }

            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            if (passphrase == NULL) {
                if (session->common.callbacks && session->common.callbacks->auth_function) {
                    rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, pem_get_password, session);
                } else {
                    /* openssl uses its own callback to get the passphrase here */
                    rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, NULL);
                }
            } else {
                rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, (void *) passphrase);
            }

            BIO_free(mem);

            if (rsa == NULL) {
                ssh_set_error(session, SSH_FATAL,
                              "Parsing private key: %s",
                              ERR_error_string(ERR_get_error(),NULL));
                return NULL;
            }

            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            BIO_free(mem);
            ssh_set_error(session, SSH_FATAL,
                          "Unkown or invalid private key type %d", type);
            return NULL;
    }

    key = ssh_key_new();
    if (key == NULL) {
        goto fail;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC;
    key->dsa = dsa;
    key->rsa = rsa;

    return key;
fail:
    ssh_key_free(key);
    DSA_free(dsa);
    RSA_free(rsa);

    return NULL;
}

#endif /* _PKI_CRYPTO_H */
