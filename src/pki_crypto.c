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
#include "libssh/buffer.h"
#include "libssh/session.h"
#include "libssh/callbacks.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/keys.h"
#include "libssh/dh.h"

struct pem_get_password_struct {
    ssh_auth_callback fn;
    void *data;
};

static int pem_get_password(char *buf, int size, int rwflag, void *userdata) {
    struct pem_get_password_struct *pgp = userdata;

    (void) rwflag; /* unused */

    if (buf == NULL) {
        return 0;
    }

    memset(buf, '\0', size);
    if (pgp) {
        int rc;

        rc = pgp->fn("Passphrase for private key:",
                     buf, size, 0, 0,
                     pgp->data);
        if (rc == 0) {
            return strlen(buf);
        }
    }

    return 0;
}

ssh_key pki_key_dup(const ssh_key key, int demote)
{
    ssh_key new;

    new = ssh_key_new();
    if (new == NULL) {
        return NULL;
    }

    new->type = key->type;
    new->type_c = key->type_c;
    if (demote) {
        new->flags = SSH_KEY_FLAG_PUBLIC;
    } else {
        new->flags = key->flags;
    }

    switch (key->type) {
    case SSH_KEYTYPE_DSS:
        new->dsa = DSA_new();
        if (new->dsa == NULL) {
            goto fail;
        }

        /*
         * p        = public prime number
         * q        = public 160-bit subprime, q | p-1
         * g        = public generator of subgroup
         * pub_key  = public key y = g^x
         * priv_key = private key x
         */
        new->dsa->p = BN_dup(key->dsa->p);
        if (new->dsa->p == NULL) {
            goto fail;
        }

        new->dsa->q = BN_dup(key->dsa->q);
        if (new->dsa->q == NULL) {
            goto fail;
        }

        new->dsa->g = BN_dup(key->dsa->g);
        if (new->dsa->g == NULL) {
            goto fail;
        }

        new->dsa->pub_key = BN_dup(key->dsa->pub_key);
        if (new->dsa->pub_key == NULL) {
            goto fail;
        }

        if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE)) {
            new->dsa->priv_key = BN_dup(key->dsa->priv_key);
            if (new->dsa->priv_key == NULL) {
                goto fail;
            }
        }

        break;
    case SSH_KEYTYPE_RSA:
    case SSH_KEYTYPE_RSA1:
        new->rsa = RSA_new();
        if (new->rsa == NULL) {
            goto fail;
        }

        /*
         * n    = public modulus
         * e    = public exponent
         * d    = private exponent
         * p    = secret prime factor
         * q    = secret prime factor
         * dmp1 = d mod (p-1)
         * dmq1 = d mod (q-1)
         * iqmp = q^-1 mod p
         */
        new->rsa->n = BN_dup(key->rsa->n);
        if (new->rsa->n == NULL) {
            goto fail;
        }

        new->rsa->e = BN_dup(key->rsa->e);
        if (new->rsa->e == NULL) {
            goto fail;
        }

        if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE)) {
            new->rsa->d = BN_dup(key->rsa->d);
            if (new->rsa->d == NULL) {
                goto fail;
            }

            /* p, q, dmp1, dmq1 and iqmp may be NULL in private keys, but the
             * RSA operations are much faster when these values are available.
             */
            if (key->rsa->p != NULL) {
                new->rsa->p = BN_dup(key->rsa->p);
                if (new->rsa->p == NULL) {
                    goto fail;
                }
            }

            if (key->rsa->q != NULL) {
                new->rsa->q = BN_dup(key->rsa->q);
                if (new->rsa->q == NULL) {
                    goto fail;
                }
            }

            if (key->rsa->dmp1 != NULL) {
                new->rsa->dmp1 = BN_dup(key->rsa->dmp1);
                if (new->rsa->dmp1 == NULL) {
                    goto fail;
                }
            }

            if (key->rsa->dmq1 != NULL) {
                new->rsa->dmq1 = BN_dup(key->rsa->dmq1);
                if (new->rsa->dmq1 == NULL) {
                    goto fail;
                }
            }

            if (key->rsa->iqmp != NULL) {
                new->rsa->iqmp = BN_dup(key->rsa->iqmp);
                if (new->rsa->iqmp == NULL) {
                    goto fail;
                }
            }
        }

        break;
    case SSH_KEYTYPE_ECDSA:
    case SSH_KEYTYPE_UNKNOWN:
        ssh_key_free(new);
        return NULL;
    }

    return new;
fail:
    ssh_key_free(new);
    return NULL;
}

ssh_key pki_private_key_from_base64(const char *b64_key,
                                    const char *passphrase,
                                    ssh_auth_callback auth_fn,
                                    void *auth_data) {
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
        ssh_pki_log("Unknown or invalid private key.");
        return NULL;
    }

    mem = BIO_new_mem_buf((void*)b64_key, -1);

    switch (type) {
        case SSH_KEYTYPE_DSS:
            if (passphrase == NULL) {
                if (auth_fn) {
                    struct pem_get_password_struct pgp = { auth_fn, auth_data };

                    dsa = PEM_read_bio_DSAPrivateKey(mem, NULL, pem_get_password, &pgp);
                } else {
                    /* openssl uses its own callback to get the passphrase here */
                    dsa = PEM_read_bio_DSAPrivateKey(mem, NULL, NULL, NULL);
                }
            } else {
                dsa = PEM_read_bio_DSAPrivateKey(mem, NULL, NULL, (void *) passphrase);
            }

            BIO_free(mem);

            if (dsa == NULL) {
                ssh_pki_log("Parsing private key: %s",
                            ERR_error_string(ERR_get_error(), NULL));
                return NULL;
            }

            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            if (passphrase == NULL) {
                if (auth_fn) {
                    struct pem_get_password_struct pgp = { auth_fn, auth_data };

                    rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, pem_get_password, &pgp);
                } else {
                    /* openssl uses its own callback to get the passphrase here */
                    rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, NULL);
                }
            } else {
                rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, (void *) passphrase);
            }

            BIO_free(mem);

            if (rsa == NULL) {
                ssh_pki_log("Parsing private key: %s",
                            ERR_error_string(ERR_get_error(),NULL));
                return NULL;
            }

            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            BIO_free(mem);
            ssh_pki_log("Unkown or invalid private key type %d", type);
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

ssh_string pki_publickey_to_blob(const ssh_key key)
{
    ssh_buffer buffer;
    ssh_string type_s;
    ssh_string str = NULL;
    ssh_string e = NULL;
    ssh_string n = NULL;
    ssh_string p = NULL;
    ssh_string g = NULL;
    ssh_string q = NULL;
    int rc;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        return NULL;
    }

    type_s = ssh_string_from_char(key->type_c);
    if (type_s == NULL) {
        ssh_buffer_free(buffer);
        return NULL;
    }

    rc = buffer_add_ssh_string(buffer, type_s);
    string_free(type_s);
    if (rc < 0) {
        ssh_buffer_free(buffer);
        return NULL;
    }

    switch (key->type) {
        case SSH_KEYTYPE_DSS:
            p = make_bignum_string(key->dsa->p);
            if (p == NULL) {
                goto fail;
            }

            q = make_bignum_string(key->dsa->q);
            if (q == NULL) {
                goto fail;
            }

            g = make_bignum_string(key->dsa->g);
            if (g == NULL) {
                goto fail;
            }

            n = make_bignum_string(key->dsa->pub_key);
            if (n == NULL) {
                goto fail;
            }

            if (buffer_add_ssh_string(buffer, p) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, q) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, g) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, n) < 0) {
                goto fail;
            }

            ssh_string_burn(p);
            ssh_string_free(p);
            ssh_string_burn(g);
            ssh_string_free(g);
            ssh_string_burn(q);
            ssh_string_free(q);
            ssh_string_burn(n);
            ssh_string_free(n);

            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            e = make_bignum_string(key->rsa->e);
            if (e == NULL) {
                goto fail;
            }

            n = make_bignum_string(key->rsa->n);
            if (n == NULL) {
                goto fail;
            }

            if (buffer_add_ssh_string(buffer, e) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, n) < 0) {
                goto fail;
            }

            ssh_string_burn(e);
            ssh_string_free(e);
            ssh_string_burn(n);
            ssh_string_free(n);

            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            goto fail;
    }

    str = ssh_string_new(buffer_get_rest_len(buffer));
    if (str == NULL) {
        goto fail;
    }

    rc = ssh_string_fill(str, buffer_get_rest(buffer), buffer_get_rest_len(buffer));
    if (rc < 0) {
        goto fail;
    }
    ssh_buffer_free(buffer);

    return str;
fail:
    ssh_buffer_free(buffer);
    ssh_string_burn(str);
    ssh_string_free(str);
    ssh_string_burn(e);
    ssh_string_free(e);
    ssh_string_burn(p);
    ssh_string_free(p);
    ssh_string_burn(g);
    ssh_string_free(g);
    ssh_string_burn(q);
    ssh_string_free(q);
    ssh_string_burn(n);
    ssh_string_free(n);

    return NULL;
}

static ssh_string _RSA_do_sign(const unsigned char *payload,
                               int len,
                               RSA *privkey)
{
    ssh_string sign = NULL;
    unsigned char *buffer = NULL;
    unsigned int size;

    buffer = malloc(RSA_size(privkey));
    if (buffer == NULL) {
        return NULL;
    }

    if (RSA_sign(NID_sha1, payload, len, buffer, &size, privkey) == 0) {
        SAFE_FREE(buffer);
        return NULL;
    }

    sign = ssh_string_new(size);
    if (sign == NULL) {
        SAFE_FREE(buffer);
        return NULL;
    }

    ssh_string_fill(sign, buffer, size);
    SAFE_FREE(buffer);

    return sign;
}

ssh_string pki_signature_to_blob(const ssh_signature sig)
{
    char buffer[40] = {0};
    ssh_string sig_blob = NULL;
    ssh_string r;
    ssh_string s;

    switch(sig->type) {
        case SSH_KEYTYPE_DSS:
            r = make_bignum_string(sig->dsa_sig->r);
            if (r == NULL) {
                return NULL;
            }
            s = make_bignum_string(sig->dsa_sig->s);
            if (s == NULL) {
                ssh_string_free(r);
                return NULL;
            }

            memcpy(buffer,
                   ((char *)ssh_string_data(r)) + ssh_string_len(r) - 20,
                   20);
            memcpy(buffer + 20,
                   ((char *)ssh_string_data(s)) + ssh_string_len(s) - 20,
                   20);

            ssh_string_free(r);
            ssh_string_free(s);

            sig_blob = ssh_string_new(40);
            if (sig_blob == NULL) {
                return NULL;
            }

            ssh_string_fill(sig_blob, buffer, 40);
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sig_blob = string_copy(sig->rsa_sig);
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            ssh_pki_log("Unknown signature key type: %d", sig->type);
            return NULL;
    }

    return sig_blob;
}

ssh_signature pki_signature_from_blob(const ssh_key pubkey,
                                      const ssh_string sig_blob,
                                      enum ssh_keytypes_e type)
{
    ssh_signature sig;
    ssh_string r;
    ssh_string s;
    size_t len;
    size_t rsalen;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }

    sig->type = type;

    len = ssh_string_len(sig_blob);

    switch(type) {
        case SSH_KEYTYPE_DSS:
            /* 40 is the dual signature blob len. */
            if (len != 40) {
                ssh_pki_log("Signature has wrong size: %lu",
                            (unsigned long)len);
                ssh_signature_free(sig);
                return NULL;
            }

#ifdef DEBUG_CRYPTO
            ssh_print_hexa("r", ssh_string_data(str), 20);
            ssh_print_hexa("s", (unsigned char *)ssh_string_data(rs) + 20, 20);
#endif

            sig->dsa_sig = DSA_SIG_new();
            if (sig->dsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

            r = ssh_string_new(20);
            if (r == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            ssh_string_fill(r, ssh_string_data(sig_blob), 20);

            sig->dsa_sig->r = make_string_bn(r);
            ssh_string_free(r);
            if (sig->dsa_sig->r == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

            s = ssh_string_new(20);
            if (s == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            ssh_string_fill(s, (char *)ssh_string_data(sig_blob) + 20, 20);

            sig->dsa_sig->s = make_string_bn(s);
            ssh_string_free(s);
            if (sig->dsa_sig->s == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            rsalen = RSA_size(pubkey->rsa);

            if (len > rsalen) {
                ssh_pki_log("Signature is to big size: %lu",
                            (unsigned long)len);
                ssh_signature_free(sig);
                return NULL;
            }

            if (len < rsalen) {
                ssh_pki_log("RSA signature len %lu < %lu",
                            (unsigned long)len, (unsigned long)rsalen);
            }

#ifdef DEBUG_CRYPTO
            ssh_pki_log("RSA signature len: %lu", (unsigned long)len);
            ssh_print_hexa("RSA signature", ssh_string_data(sig_blob), len);
#endif
            sig->rsa_sig = string_copy(sig_blob);
            if (sig->rsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            ssh_pki_log("Unknown signature type");
            return NULL;
    }

    return sig;
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
            sign->rsa_sign = _RSA_do_sign(hash + 1, SHA_DIGEST_LEN,
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

#ifdef WITH_SERVER
ssh_signature pki_do_sign_sessionid(const ssh_key key,
                                    const unsigned char *hash)
{
    ssh_signature sig;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }
    sig->type = key->type;

    switch(key->type) {
        case SSH_KEYTYPE_DSS:
            sig->dsa_sig = DSA_do_sign(hash + 1, SHA_DIGEST_LEN, key->dsa);
            if (sig->dsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sig->rsa_sig = _RSA_do_sign(hash + 1, SHA_DIGEST_LEN, key->rsa);
            if (sig->rsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            return NULL;
    }

    return sig;
}
#endif /* WITH_SERVER */

#endif /* _PKI_CRYPTO_H */
