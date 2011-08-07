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

#include <openssl/pem.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "libssh/priv.h"
#include "libssh/libssh.h"
#include "libssh/session.h"
#include "libssh/callbacks.h"
#include "libssh/pki.h"
#include "libssh/keys.h"
#include "libssh/dh.h"

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

int pki_pubkey_build_dss(ssh_key key,
                         ssh_string p,
                         ssh_string q,
                         ssh_string g,
                         ssh_string pubkey) {
    key->dsa = DSA_new();
    if (key->dsa == NULL) {
        return SSH_ERROR;
    }

    key->dsa->p = make_string_bn(p);
    key->dsa->q = make_string_bn(q);
    key->dsa->g = make_string_bn(g);
    key->dsa->pub_key = make_string_bn(pubkey);
    if (key->dsa->p == NULL ||
        key->dsa->q == NULL ||
        key->dsa->g == NULL ||
        key->dsa->pub_key == NULL) {
        DSA_free(key->dsa);
        return SSH_ERROR;
    }

    return SSH_OK;
}

int pki_pubkey_build_rsa(ssh_key key,
                         ssh_string e,
                         ssh_string n) {
    key->rsa = RSA_new();
    if (key->rsa == NULL) {
        return SSH_ERROR;
    }

    key->rsa->e = make_string_bn(e);
    key->rsa->n = make_string_bn(n);
    if (key->rsa->e == NULL ||
        key->rsa->n == NULL) {
        RSA_free(key->rsa);
        return SSH_ERROR;
    }

    return SSH_OK;
}

ssh_key pki_publickey_from_privatekey(ssh_key privkey) {
    ssh_key pubkey = NULL;

    if (privkey == NULL || !ssh_key_is_private(privkey)) {
        return NULL;
    }

    pubkey = ssh_key_new();
    if (pubkey == NULL) {
        return NULL;
    }
    pubkey->type = privkey->type;

    switch (pubkey->type) {
        case SSH_KEYTYPE_DSS:
            pubkey->dsa = DSA_new();
            if (pubkey->dsa == NULL) {
                goto fail;
            }
            pubkey->dsa->p = BN_dup(privkey->dsa->p);
            pubkey->dsa->q = BN_dup(privkey->dsa->q);
            pubkey->dsa->g = BN_dup(privkey->dsa->g);
            pubkey->dsa->pub_key = BN_dup(privkey->dsa->pub_key);
            if (pubkey->dsa->p == NULL ||
                    pubkey->dsa->q == NULL ||
                    pubkey->dsa->g == NULL ||
                    pubkey->dsa->pub_key == NULL) {
                goto fail;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            pubkey->rsa = RSA_new();
            if (pubkey->rsa == NULL) {
                goto fail;
            }
            pubkey->rsa->e = BN_dup(privkey->rsa->e);
            pubkey->rsa->n = BN_dup(privkey->rsa->n);
            if (pubkey->rsa->e == NULL ||
                    pubkey->rsa->n == NULL) {
                goto fail;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            ssh_key_free(pubkey);
            return NULL;
    }
    pubkey->type_c = ssh_key_type_to_char(privkey->type);

    return pubkey;
fail:
    ssh_key_free(pubkey);

    return NULL;
}

struct signature_struct *pki_do_sign(ssh_key privatekey,
                                     const unsigned char *hash) {
    struct signature_struct *sign;

    sign = malloc(sizeof(SIGNATURE));
    if (sign == NULL) {
        return NULL;
    }
    sign->type = privatekey->type;

    switch(privatekey->type) {
        case SSH_KEYTYPE_DSS:
            sign->dsa_sign = DSA_do_sign(hash + 1, SHA_DIGEST_LEN,
                    privatekey->dsa);
            if (sign->dsa_sign == NULL) {
                signature_free(sign);
                return NULL;
            }

#ifdef DEBUG_CRYPTO
            ssh_print_bignum("r", sign->dsa_sign->r);
            ssh_print_bignum("s", sign->dsa_sign->s);
#endif

            sign->rsa_sign = NULL;
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sign->rsa_sign = RSA_do_sign(hash + 1, SHA_DIGEST_LEN,
                    privatekey->rsa);
            if (sign->rsa_sign == NULL) {
                signature_free(sign);
                return NULL;
            }
            sign->dsa_sign = NULL;
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            signature_free(sign);
            return NULL;
    }

    return sign;
}

#endif /* _PKI_CRYPTO_H */
