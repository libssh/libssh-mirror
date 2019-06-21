/*
 * pki_crypto.c - PKI infrastructure using OpenSSL
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 * Copyright (c) 2009-2013 by Andreas Schneider <asn@cryptomilk.org>
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

#include "libssh/priv.h"

#include <openssl/pem.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include "libcrypto-compat.h"

#ifdef HAVE_OPENSSL_EC_H
#include <openssl/ec.h>
#endif
#ifdef HAVE_OPENSSL_ECDSA_H
#include <openssl/ecdsa.h>
#endif

#include "libssh/libssh.h"
#include "libssh/buffer.h"
#include "libssh/session.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/bignum.h"

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

#ifdef HAVE_OPENSSL_ECC
static int pki_key_ecdsa_to_nid(EC_KEY *k)
{
    const EC_GROUP *g = EC_KEY_get0_group(k);
    int nid;

    nid = EC_GROUP_get_curve_name(g);
    if (nid) {
        return nid;
    }

    return -1;
}

static enum ssh_keytypes_e pki_key_ecdsa_to_key_type(EC_KEY *k)
{
    static int nid;

    nid = pki_key_ecdsa_to_nid(k);

    switch (nid) {
        case NID_X9_62_prime256v1:
            return SSH_KEYTYPE_ECDSA_P256;
        case NID_secp384r1:
            return SSH_KEYTYPE_ECDSA_P384;
        case NID_secp521r1:
            return SSH_KEYTYPE_ECDSA_P521;
        default:
            return SSH_KEYTYPE_UNKNOWN;
    }
}

const char *pki_key_ecdsa_nid_to_name(int nid)
{
    switch (nid) {
        case NID_X9_62_prime256v1:
            return "ecdsa-sha2-nistp256";
        case NID_secp384r1:
            return "ecdsa-sha2-nistp384";
        case NID_secp521r1:
            return "ecdsa-sha2-nistp521";
        default:
            break;
    }

    return "unknown";
}

static const char *pki_key_ecdsa_nid_to_char(int nid)
{
    switch (nid) {
        case NID_X9_62_prime256v1:
            return "nistp256";
        case NID_secp384r1:
            return "nistp384";
        case NID_secp521r1:
            return "nistp521";
        default:
            break;
    }

    return "unknown";
}

int pki_key_ecdsa_nid_from_name(const char *name)
{
    if (strcmp(name, "nistp256") == 0) {
        return NID_X9_62_prime256v1;
    } else if (strcmp(name, "nistp384") == 0) {
        return NID_secp384r1;
    } else if (strcmp(name, "nistp521") == 0) {
        return NID_secp521r1;
    }

    return -1;
}

static ssh_string make_ecpoint_string(const EC_GROUP *g,
                                      const EC_POINT *p)
{
    ssh_string s;
    size_t len;

    len = EC_POINT_point2oct(g,
                             p,
                             POINT_CONVERSION_UNCOMPRESSED,
                             NULL,
                             0,
                             NULL);
    if (len == 0) {
        return NULL;
    }

    s = ssh_string_new(len);
    if (s == NULL) {
        return NULL;
    }

    len = EC_POINT_point2oct(g,
                             p,
                             POINT_CONVERSION_UNCOMPRESSED,
                             ssh_string_data(s),
                             ssh_string_len(s),
                             NULL);
    if (len != ssh_string_len(s)) {
        ssh_string_free(s);
        return NULL;
    }

    return s;
}

int pki_privkey_build_ecdsa(ssh_key key, int nid, ssh_string e, ssh_string exp)
{
    EC_POINT *p = NULL;
    const EC_GROUP *g = NULL;
    int ok;
    BIGNUM *bexp = NULL;

    key->ecdsa_nid = nid;
    key->type_c = pki_key_ecdsa_nid_to_name(nid);

    key->ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid);
    if (key->ecdsa == NULL) {
        return -1;
    }

    g = EC_KEY_get0_group(key->ecdsa);

    p = EC_POINT_new(g);
    if (p == NULL) {
        return -1;
    }

    ok = EC_POINT_oct2point(g,
                            p,
                            ssh_string_data(e),
                            ssh_string_len(e),
                            NULL);
    if (!ok) {
        EC_POINT_free(p);
        return -1;
    }

    /* EC_KEY_set_public_key duplicates p */
    ok = EC_KEY_set_public_key(key->ecdsa, p);
    EC_POINT_free(p);
    if (!ok) {
        return -1;
    }

    bexp = ssh_make_string_bn(exp);
    if (bexp == NULL) {
        EC_KEY_free(key->ecdsa);
        return -1;
    }
    /* EC_KEY_set_private_key duplicates exp */
    ok = EC_KEY_set_private_key(key->ecdsa, bexp);
    BN_free(bexp);
    if (!ok) {
        EC_KEY_free(key->ecdsa);
        return -1;
    }

    return 0;
}

int pki_pubkey_build_ecdsa(ssh_key key, int nid, ssh_string e)
{
    EC_POINT *p = NULL;
    const EC_GROUP *g = NULL;
    int ok;

    key->ecdsa_nid = nid;
    key->type_c = pki_key_ecdsa_nid_to_name(nid);

    key->ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid);
    if (key->ecdsa == NULL) {
        return -1;
    }

    g = EC_KEY_get0_group(key->ecdsa);

    p = EC_POINT_new(g);
    if (p == NULL) {
        return -1;
    }

    ok = EC_POINT_oct2point(g,
                            p,
                            ssh_string_data(e),
                            ssh_string_len(e),
                            NULL);
    if (!ok) {
        EC_POINT_free(p);
        return -1;
    }

    /* EC_KEY_set_public_key duplicates p */
    ok = EC_KEY_set_public_key(key->ecdsa, p);
    EC_POINT_free(p);
    if (!ok) {
        return -1;
    }

    return 0;
}
#endif

ssh_key pki_key_dup(const ssh_key key, int demote)
{
    ssh_key new;
    int rc;

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
    case SSH_KEYTYPE_DSS: {
        const BIGNUM *p = NULL, *q = NULL, *g = NULL,
          *pub_key = NULL, *priv_key = NULL;
        BIGNUM *np, *nq, *ng, *npub_key, *npriv_key;
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
        DSA_get0_pqg(key->dsa, &p, &q, &g);
        np = BN_dup(p);
        nq = BN_dup(q);
        ng = BN_dup(g);
        if (np == NULL || nq == NULL || ng == NULL) {
            BN_free(np);
            BN_free(nq);
            BN_free(ng);
            goto fail;
        }

        /* Memory management of np, nq and ng is transferred to DSA object */
        rc = DSA_set0_pqg(new->dsa, np, nq, ng);
        if (rc == 0) {
            BN_free(np);
            BN_free(nq);
            BN_free(ng);
            goto fail;
        }

        DSA_get0_key(key->dsa, &pub_key, &priv_key);
        npub_key = BN_dup(pub_key);
        if (npub_key == NULL) {
            goto fail;
        }

        /* Memory management of npubkey is transferred to DSA object */
        rc = DSA_set0_key(new->dsa, npub_key, NULL);
        if (rc == 0) {
            goto fail;
        }

        if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE)) {
            npriv_key = BN_dup(priv_key);
            if (npriv_key == NULL) {
                goto fail;
            }

            /* Memory management of npriv_key is transferred to DSA object */
            rc = DSA_set0_key(new->dsa, NULL, npriv_key);
            if (rc == 0) {
                goto fail;
            }
        }

        break;
    }
    case SSH_KEYTYPE_RSA:
    case SSH_KEYTYPE_RSA1: {
        const BIGNUM *n = NULL, *e = NULL, *d = NULL;
        BIGNUM *nn, *ne, *nd;
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
        RSA_get0_key(key->rsa, &n, &e, &d);
        nn = BN_dup(n);
        ne = BN_dup(e);
        if (nn == NULL || ne == NULL) {
            BN_free(nn);
            BN_free(ne);
            goto fail;
        }

        /* Memory management of nn and ne is transferred to RSA object */
        rc = RSA_set0_key(new->rsa, nn, ne, NULL);
        if (rc == 0) {
            BN_free(nn);
            BN_free(ne);
            goto fail;
        }

        if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE)) {
            const BIGNUM *p = NULL, *q = NULL, *dmp1 = NULL,
              *dmq1 = NULL, *iqmp = NULL;
            BIGNUM *np, *nq, *ndmp1, *ndmq1, *niqmp;

            nd = BN_dup(d);
            if (nd == NULL) {
                goto fail;
            }

            /* Memory management of nd is transferred to RSA object */
            rc = RSA_set0_key(new->rsa, NULL, NULL, nd);
            if (rc == 0) {
                goto fail;
            }

            /* p, q, dmp1, dmq1 and iqmp may be NULL in private keys, but the
             * RSA operations are much faster when these values are available.
             */
            RSA_get0_factors(key->rsa, &p, &q);
            if (p != NULL && q != NULL) { /* need to set both of them */
                np = BN_dup(p);
                nq = BN_dup(q);
                if (np == NULL || nq == NULL) {
                    BN_free(np);
                    BN_free(nq);
                    goto fail;
                }

                /* Memory management of np and nq is transferred to RSA object */
                rc = RSA_set0_factors(new->rsa, np, nq);
                if (rc == 0) {
                    BN_free(np);
                    BN_free(nq);
                    goto fail;
                }
            }

            RSA_get0_crt_params(key->rsa, &dmp1, &dmq1, &iqmp);
            if (dmp1 != NULL || dmq1 != NULL || iqmp != NULL) {
                ndmp1 = BN_dup(dmp1);
                ndmq1 = BN_dup(dmq1);
                niqmp = BN_dup(iqmp);
                if (ndmp1 == NULL || ndmq1 == NULL || niqmp == NULL) {
                    BN_free(ndmp1);
                    BN_free(ndmq1);
                    BN_free(niqmp);
                    goto fail;
                }

                /* Memory management of ndmp1, ndmq1 and niqmp is transferred
                 * to RSA object */
                rc =  RSA_set0_crt_params(new->rsa, ndmp1, ndmq1, niqmp);
                if (rc == 0) {
                    BN_free(ndmp1);
                    BN_free(ndmq1);
                    BN_free(niqmp);
                    goto fail;
                }
            }
        }

        break;
    }
    case SSH_KEYTYPE_ECDSA_P256:
    case SSH_KEYTYPE_ECDSA_P384:
    case SSH_KEYTYPE_ECDSA_P521:
#ifdef HAVE_OPENSSL_ECC
        new->ecdsa_nid = key->ecdsa_nid;

        /* privkey -> pubkey */
        if (demote && ssh_key_is_private(key)) {
            const EC_POINT *p;
            int ok;

            new->ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid);
            if (new->ecdsa == NULL) {
                goto fail;
            }

            p = EC_KEY_get0_public_key(key->ecdsa);
            if (p == NULL) {
                goto fail;
            }

            ok = EC_KEY_set_public_key(new->ecdsa, p);
            if (!ok) {
                goto fail;
            }
        } else {
            new->ecdsa = EC_KEY_dup(key->ecdsa);
        }
        break;
#endif
    case SSH_KEYTYPE_ED25519:
        rc = pki_ed25519_key_dup(new, key);
        if (rc != SSH_OK) {
            goto fail;
        }
        break;
    case SSH_KEYTYPE_UNKNOWN:
    default:
        ssh_key_free(new);
        return NULL;
    }

    return new;
fail:
    ssh_key_free(new);
    return NULL;
}

int pki_key_generate_rsa(ssh_key key, int parameter){
	BIGNUM *e;
	int rc;

	e = BN_new();
	key->rsa = RSA_new();

	BN_set_word(e, 65537);
	rc = RSA_generate_key_ex(key->rsa, parameter, e, NULL);

	BN_free(e);

	if (rc <= 0 || key->rsa == NULL)
		return SSH_ERROR;
	return SSH_OK;
}

int pki_key_generate_dss(ssh_key key, int parameter){
    int rc;
#if OPENSSL_VERSION_NUMBER > 0x00908000L
    key->dsa = DSA_new();
    if (key->dsa == NULL) {
        return SSH_ERROR;
    }
    rc = DSA_generate_parameters_ex(key->dsa,
                                    parameter,
                                    NULL,  /* seed */
                                    0,     /* seed_len */
                                    NULL,  /* counter_ret */
                                    NULL,  /* h_ret */
                                    NULL); /* cb */
    if (rc != 1) {
        DSA_free(key->dsa);
        key->dsa = NULL;
        return SSH_ERROR;
    }
#else
    key->dsa = DSA_generate_parameters(parameter, NULL, 0, NULL, NULL,
            NULL, NULL);
    if(key->dsa == NULL){
        return SSH_ERROR;
    }
#endif
    rc = DSA_generate_key(key->dsa);
    if (rc != 1){
        DSA_free(key->dsa);
        key->dsa=NULL;
        return SSH_ERROR;
    }
    return SSH_OK;
}

#ifdef HAVE_OPENSSL_ECC
int pki_key_generate_ecdsa(ssh_key key, int parameter) {
    int ok;

    switch (parameter) {
        case 384:
            key->ecdsa_nid = NID_secp384r1;
            key->type = SSH_KEYTYPE_ECDSA_P384;
            break;
        case 521:
            key->ecdsa_nid = NID_secp521r1;
            key->type = SSH_KEYTYPE_ECDSA_P521;
            break;
        case 256:
            key->ecdsa_nid = NID_X9_62_prime256v1;
            key->type = SSH_KEYTYPE_ECDSA_P256;
            break;
        default:
            SSH_LOG(SSH_LOG_WARN, "Invalid parameter %d for ECDSA key "
                    "generation", parameter);
            return SSH_ERROR;
    }

    key->ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid);
    if (key->ecdsa == NULL) {
        return SSH_ERROR;
    }

    ok = EC_KEY_generate_key(key->ecdsa);
    if (!ok) {
        EC_KEY_free(key->ecdsa);
        return SSH_ERROR;
    }

    EC_KEY_set_asn1_flag(key->ecdsa, OPENSSL_EC_NAMED_CURVE);

    return SSH_OK;
}
#endif

int pki_key_compare(const ssh_key k1,
                    const ssh_key k2,
                    enum ssh_keycmp_e what)
{
    switch (k1->type) {
        case SSH_KEYTYPE_DSS: {
            const BIGNUM *p1, *p2, *q1, *q2, *g1, *g2,
                *pub_key1, *pub_key2, *priv_key1, *priv_key2;
            if (DSA_size(k1->dsa) != DSA_size(k2->dsa)) {
                return 1;
            }
            DSA_get0_pqg(k1->dsa, &p1, &q1, &g1);
            DSA_get0_pqg(k2->dsa, &p2, &q2, &g2);
            if (bignum_cmp(p1, p2) != 0) {
                return 1;
            }
            if (bignum_cmp(q1, q2) != 0) {
                return 1;
            }
            if (bignum_cmp(g1, g2) != 0) {
                return 1;
            }
            DSA_get0_key(k1->dsa, &pub_key1, &priv_key1);
            DSA_get0_key(k2->dsa, &pub_key2, &priv_key2);
            if (bignum_cmp(pub_key1, pub_key2) != 0) {
                return 1;
            }

            if (what == SSH_KEY_CMP_PRIVATE) {
                if (bignum_cmp(priv_key1, priv_key2) != 0) {
                    return 1;
                }
            }
            break;
        }
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1: {
            const BIGNUM *e1, *e2, *n1, *n2, *p1, *p2, *q1, *q2;
            if (RSA_size(k1->rsa) != RSA_size(k2->rsa)) {
                return 1;
            }
            RSA_get0_key(k1->rsa, &n1, &e1, NULL);
            RSA_get0_key(k2->rsa, &n2, &e2, NULL);
            if (bignum_cmp(e1, e2) != 0) {
                return 1;
            }
            if (bignum_cmp(n1, n2) != 0) {
                return 1;
            }

            if (what == SSH_KEY_CMP_PRIVATE) {
                RSA_get0_factors(k1->rsa, &p1, &q1);
                RSA_get0_factors(k2->rsa, &p2, &q2);
                if (bignum_cmp(p1, p2) != 0) {
                    return 1;
                }

                if (bignum_cmp(q1, q2) != 0) {
                    return 1;
                }
            }
            break;
        }
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
#ifdef HAVE_OPENSSL_ECC
            {
                const EC_POINT *p1 = EC_KEY_get0_public_key(k1->ecdsa);
                const EC_POINT *p2 = EC_KEY_get0_public_key(k2->ecdsa);
                const EC_GROUP *g1 = EC_KEY_get0_group(k1->ecdsa);
                const EC_GROUP *g2 = EC_KEY_get0_group(k2->ecdsa);

                if (p1 == NULL || p2 == NULL) {
                    return 1;
                }

                if (EC_GROUP_cmp(g1, g2, NULL) != 0) {
                    return 1;
                }

                if (EC_POINT_cmp(g1, p1, p2, NULL) != 0) {
                    return 1;
                }

                if (what == SSH_KEY_CMP_PRIVATE) {
                    if (bignum_cmp(EC_KEY_get0_private_key(k1->ecdsa),
                                   EC_KEY_get0_private_key(k2->ecdsa))) {
                        return 1;
                    }
                }

                break;
            }
#endif
        case SSH_KEYTYPE_ED25519:
            /* ed25519 keys handled globaly */
        case SSH_KEYTYPE_UNKNOWN:
        default:
            return 1;
    }

    return 0;
}

ssh_string pki_private_key_to_pem(const ssh_key key,
                                  const char *passphrase,
                                  ssh_auth_callback auth_fn,
                                  void *auth_data)
{
    ssh_string blob = NULL;
    BUF_MEM *buf = NULL;
    BIO *mem = NULL;
    EVP_PKEY *pkey = NULL;
    int rc;

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        return NULL;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        goto err;
    }

    switch (key->type) {
        case SSH_KEYTYPE_DSS:
            rc = EVP_PKEY_set1_DSA(pkey, key->dsa);
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            rc = EVP_PKEY_set1_RSA(pkey, key->rsa);
            break;
#ifdef HAVE_ECC
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
            rc = EVP_PKEY_set1_EC_KEY(pkey, key->ecdsa);
            break;
#endif
        case SSH_KEYTYPE_ED25519:
            SSH_LOG(SSH_LOG_WARN, "PEM output not supported for key type ssh-ed25519");
            goto err;
        case SSH_KEYTYPE_DSS_CERT01:
        case SSH_KEYTYPE_RSA_CERT01:
        case SSH_KEYTYPE_ECDSA_P256_CERT01:
        case SSH_KEYTYPE_ECDSA_P384_CERT01:
        case SSH_KEYTYPE_ECDSA_P521_CERT01:
        case SSH_KEYTYPE_ED25519_CERT01:
        case SSH_KEYTYPE_UNKNOWN:
        default:
            SSH_LOG(SSH_LOG_WARN, "Unknown or invalid private key type %d", key->type);
            goto err;
    }
    if (rc != 1) {
        SSH_LOG(SSH_LOG_WARN, "Failed to initialize EVP_PKEY structure");
        goto err;
    }

    if (passphrase == NULL) {
        struct pem_get_password_struct pgp = { auth_fn, auth_data };

        rc = PEM_write_bio_PrivateKey(mem,
                                      pkey,
                                      NULL, /* cipher */
                                      NULL, /* kstr */
                                      0, /* klen */
                                      pem_get_password,
                                      &pgp);
    } else {
        rc = PEM_write_bio_PrivateKey(mem,
                                      pkey,
                                      EVP_aes_128_cbc(),
                                      NULL, /* kstr */
                                      0, /* klen */
                                      NULL, /* auth_fn */
                                      (void*) passphrase);
    }
    EVP_PKEY_free(pkey);
    pkey = NULL;

    if (rc != 1) {
        goto err;
    }

    BIO_get_mem_ptr(mem, &buf);

    blob = ssh_string_new(buf->length);
    if (blob == NULL) {
        goto err;
    }

    ssh_string_fill(blob, buf->data, buf->length);
    BIO_free(mem);

    return blob;

err:
    EVP_PKEY_free(pkey);
    BIO_free(mem);
    return NULL;
}

ssh_key pki_private_key_from_base64(const char *b64_key,
                                    const char *passphrase,
                                    ssh_auth_callback auth_fn,
                                    void *auth_data)
{
    BIO *mem = NULL;
    DSA *dsa = NULL;
    RSA *rsa = NULL;
    ed25519_privkey *ed25519 = NULL;
    ssh_key key = NULL;
    enum ssh_keytypes_e type = SSH_KEYTYPE_UNKNOWN;
#ifdef HAVE_OPENSSL_ECC
    EC_KEY *ecdsa = NULL;
#else
    void *ecdsa = NULL;
#endif
    EVP_PKEY *pkey = NULL;

    mem = BIO_new_mem_buf((void*)b64_key, -1);

    if (passphrase == NULL) {
        if (auth_fn) {
            struct pem_get_password_struct pgp = { auth_fn, auth_data };

            pkey = PEM_read_bio_PrivateKey(mem, NULL, pem_get_password, &pgp);
        } else {
            /* openssl uses its own callback to get the passphrase here */
            pkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
        }
    } else {
        pkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, (void *) passphrase);
    }

    BIO_free(mem);

    if (pkey == NULL) {
        SSH_LOG(SSH_LOG_WARN,
                "Parsing private key: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    switch (EVP_PKEY_base_id(pkey)) {
    case EVP_PKEY_DSA:
        dsa = EVP_PKEY_get1_DSA(pkey);
        if (dsa == NULL) {
            SSH_LOG(SSH_LOG_WARN,
                    "Parsing private key: %s",
                    ERR_error_string(ERR_get_error(),NULL));
            return NULL;
        }
        type = SSH_KEYTYPE_DSS;
        break;
    case EVP_PKEY_RSA:
        rsa = EVP_PKEY_get1_RSA(pkey);
        if (rsa == NULL) {
            SSH_LOG(SSH_LOG_WARN,
                    "Parsing private key: %s",
                    ERR_error_string(ERR_get_error(),NULL));
            return NULL;
        }
        type = SSH_KEYTYPE_RSA;
        break;
    case EVP_PKEY_EC:
#ifdef HAVE_OPENSSL_ECC
        ecdsa = EVP_PKEY_get1_EC_KEY(pkey);
        if (ecdsa == NULL) {
            SSH_LOG(SSH_LOG_WARN,
                    "Parsing private key: %s",
                    ERR_error_string(ERR_get_error(), NULL));
            return NULL;
        }

        /* pki_privatekey_type_from_string always returns P256 for ECDSA
         * keys, so we need to figure out the correct type here */
        type = pki_key_ecdsa_to_key_type(ecdsa);
        if (type == SSH_KEYTYPE_UNKNOWN) {
            SSH_LOG(SSH_LOG_WARN, "Invalid private key.");
            goto fail;
        }

        break;
#endif
    default:
        EVP_PKEY_free(pkey);
        SSH_LOG(SSH_LOG_WARN, "Unknown or invalid private key type %d",
                EVP_PKEY_base_id(pkey));
        return NULL;
    }
    EVP_PKEY_free(pkey);

    key = ssh_key_new();
    if (key == NULL) {
        goto fail;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC;
    key->dsa = dsa;
    key->rsa = rsa;
    key->ecdsa = ecdsa;
    key->ed25519_privkey = ed25519;
#ifdef HAVE_OPENSSL_ECC
    if (is_ecdsa_key_type(key->type)) {
        key->ecdsa_nid = pki_key_ecdsa_to_nid(key->ecdsa);
    }
#endif

    return key;
fail:
    ssh_key_free(key);
    DSA_free(dsa);
    RSA_free(rsa);
#ifdef HAVE_OPENSSL_ECC
    EC_KEY_free(ecdsa);
#endif

    return NULL;
}

int pki_privkey_build_dss(ssh_key key,
                          ssh_string p,
                          ssh_string q,
                          ssh_string g,
                          ssh_string pubkey,
                          ssh_string privkey)
{
    int rc;
    BIGNUM *bp, *bq, *bg, *bpub_key, *bpriv_key;

    key->dsa = DSA_new();
    if (key->dsa == NULL) {
        return SSH_ERROR;
    }

    bp = ssh_make_string_bn(p);
    bq = ssh_make_string_bn(q);
    bg = ssh_make_string_bn(g);
    bpub_key = ssh_make_string_bn(pubkey);
    bpriv_key = ssh_make_string_bn(privkey);
    if (bp == NULL || bq == NULL ||
        bg == NULL || bpub_key == NULL) {
        goto fail;
    }

    /* Memory management of bp, qq and bg is transferred to DSA object */
    rc = DSA_set0_pqg(key->dsa, bp, bq, bg);
    if (rc == 0) {
        goto fail;
    }

    /* Memory management of bpub_key and bpriv_key is transferred to DSA object */
    rc = DSA_set0_key(key->dsa, bpub_key, bpriv_key);
    if (rc == 0) {
        goto fail;
    }

    return SSH_OK;
fail:
    DSA_free(key->dsa);
    return SSH_ERROR;
}

int pki_pubkey_build_dss(ssh_key key,
                         ssh_string p,
                         ssh_string q,
                         ssh_string g,
                         ssh_string pubkey) {
    int rc;
    BIGNUM *bp = NULL, *bq = NULL, *bg = NULL, *bpub_key = NULL;

    key->dsa = DSA_new();
    if (key->dsa == NULL) {
        return SSH_ERROR;
    }

    bp = ssh_make_string_bn(p);
    bq = ssh_make_string_bn(q);
    bg = ssh_make_string_bn(g);
    bpub_key = ssh_make_string_bn(pubkey);
    if (bp == NULL || bq == NULL ||
        bg == NULL || bpub_key == NULL) {
        goto fail;
    }

    /* Memory management of bp, bq and bg is transferred to DSA object */
    rc = DSA_set0_pqg(key->dsa, bp, bq, bg);
    if (rc == 0) {
        goto fail;
    }

    /* Memory management of npub_key is transferred to DSA object */
    rc = DSA_set0_key(key->dsa, bpub_key, NULL);
    if (rc == 0) {
        goto fail;
    }

    return SSH_OK;
fail:
    DSA_free(key->dsa);
    return SSH_ERROR;
}

int pki_privkey_build_rsa(ssh_key key,
                          ssh_string n,
                          ssh_string e,
                          ssh_string d,
                          UNUSED_PARAM(ssh_string iqmp),
                          ssh_string p,
                          ssh_string q)
{
    int rc;
    BIGNUM *be, *bn, *bd/*, *biqmp*/, *bp, *bq;

    key->rsa = RSA_new();
    if (key->rsa == NULL) {
        return SSH_ERROR;
    }

    bn = ssh_make_string_bn(n);
    be = ssh_make_string_bn(e);
    bd = ssh_make_string_bn(d);
    /*biqmp = ssh_make_string_bn(iqmp);*/
    bp = ssh_make_string_bn(p);
    bq = ssh_make_string_bn(q);
    if (be == NULL || bn == NULL || bd == NULL ||
        /*biqmp == NULL ||*/ bp == NULL || bq == NULL) {
        goto fail;
    }

    /* Memory management of be, bn and bd is transferred to RSA object */
    rc = RSA_set0_key(key->rsa, bn, be, bd);
    if (rc == 0) {
        goto fail;
    }

    /* Memory management of bp and bq is transferred to RSA object */
    rc = RSA_set0_factors(key->rsa, bp, bq);
    if (rc == 0) {
        goto fail;
    }

    /* p, q, dmp1, dmq1 and iqmp may be NULL in private keys, but the RSA
     * operations are much faster when these values are available.
     * https://www.openssl.org/docs/man1.0.2/crypto/rsa.html
     */
    /* RSA_set0_crt_params(key->rsa, biqmp, NULL, NULL);
    TODO calculate missing crt_params */

    return SSH_OK;
fail:
    RSA_free(key->rsa);
    return SSH_ERROR;
}

int pki_pubkey_build_rsa(ssh_key key,
                         ssh_string e,
                         ssh_string n) {
    int rc;
    BIGNUM *be = NULL, *bn = NULL;

    key->rsa = RSA_new();
    if (key->rsa == NULL) {
        return SSH_ERROR;
    }

    be = ssh_make_string_bn(e);
    bn = ssh_make_string_bn(n);
    if (be == NULL || bn == NULL) {
        goto fail;
    }

    /* Memory management of bn and be is transferred to RSA object */
    rc = RSA_set0_key(key->rsa, bn, be, NULL);
    if (rc == 0) {
        goto fail;
    }

    return SSH_OK;
fail:
    RSA_free(key->rsa);
    return SSH_ERROR;
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

    if (key->cert != NULL) {
        rc = ssh_buffer_add_buffer(buffer, key->cert);
        if (rc < 0) {
            ssh_buffer_free(buffer);
            return NULL;
        }
        goto makestring;
    }

    type_s = ssh_string_from_char(key->type_c);
    if (type_s == NULL) {
        ssh_buffer_free(buffer);
        return NULL;
    }

    rc = ssh_buffer_add_ssh_string(buffer, type_s);
    ssh_string_free(type_s);
    if (rc < 0) {
        ssh_buffer_free(buffer);
        return NULL;
    }

    switch (key->type) {
        case SSH_KEYTYPE_DSS: {
            const BIGNUM *bp, *bq, *bg, *bpub_key;
            DSA_get0_pqg(key->dsa, &bp, &bq, &bg);
            p = ssh_make_bignum_string((BIGNUM *)bp);
            if (p == NULL) {
                goto fail;
            }

            q = ssh_make_bignum_string((BIGNUM *)bq);
            if (q == NULL) {
                goto fail;
            }

            g = ssh_make_bignum_string((BIGNUM *)bg);
            if (g == NULL) {
                goto fail;
            }

            DSA_get0_key(key->dsa, &bpub_key, NULL);
            n = ssh_make_bignum_string((BIGNUM *)bpub_key);
            if (n == NULL) {
                goto fail;
            }

            if (ssh_buffer_add_ssh_string(buffer, p) < 0) {
                goto fail;
            }
            if (ssh_buffer_add_ssh_string(buffer, q) < 0) {
                goto fail;
            }
            if (ssh_buffer_add_ssh_string(buffer, g) < 0) {
                goto fail;
            }
            if (ssh_buffer_add_ssh_string(buffer, n) < 0) {
                goto fail;
            }

            ssh_string_burn(p);
            ssh_string_free(p);
            p = NULL;
            ssh_string_burn(g);
            ssh_string_free(g);
            g = NULL;
            ssh_string_burn(q);
            ssh_string_free(q);
            q = NULL;
            ssh_string_burn(n);
            ssh_string_free(n);
            n = NULL;

            break;
        }
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1: {
            const BIGNUM *be, *bn;
            RSA_get0_key(key->rsa, &bn, &be, NULL);
            e = ssh_make_bignum_string((BIGNUM *)be);
            if (e == NULL) {
                goto fail;
            }

            n = ssh_make_bignum_string((BIGNUM *)bn);
            if (n == NULL) {
                goto fail;
            }

            if (ssh_buffer_add_ssh_string(buffer, e) < 0) {
                goto fail;
            }
            if (ssh_buffer_add_ssh_string(buffer, n) < 0) {
                goto fail;
            }

            ssh_string_burn(e);
            ssh_string_free(e);
            e = NULL;
            ssh_string_burn(n);
            ssh_string_free(n);
            n = NULL;

            break;
        }
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_public_key_to_blob(buffer, key);
            if (rc == SSH_ERROR){
                goto fail;
            }
            break;
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
#ifdef HAVE_OPENSSL_ECC
            type_s = ssh_string_from_char(pki_key_ecdsa_nid_to_char(key->ecdsa_nid));
            if (type_s == NULL) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            rc = ssh_buffer_add_ssh_string(buffer, type_s);
            ssh_string_free(type_s);
            if (rc < 0) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            e = make_ecpoint_string(EC_KEY_get0_group(key->ecdsa),
                                    EC_KEY_get0_public_key(key->ecdsa));
            if (e == NULL) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            rc = ssh_buffer_add_ssh_string(buffer, e);
            if (rc < 0) {
                goto fail;
            }

            ssh_string_burn(e);
            ssh_string_free(e);
            e = NULL;

            break;
#endif
        case SSH_KEYTYPE_UNKNOWN:
        default:
            goto fail;
    }

makestring:
    str = ssh_string_new(ssh_buffer_get_len(buffer));
    if (str == NULL) {
        goto fail;
    }

    rc = ssh_string_fill(str, ssh_buffer_get(buffer), ssh_buffer_get_len(buffer));
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

static ssh_string pki_dsa_signature_to_blob(const ssh_signature sig)
{
    char buffer[40] = { 0 };
    ssh_string sig_blob = NULL;
    const BIGNUM *pr = NULL, *ps = NULL;

    ssh_string r = NULL;
    int r_len, r_offset_in, r_offset_out;

    ssh_string s = NULL;
    int s_len, s_offset_in, s_offset_out;

    const unsigned char *raw_sig_data = NULL;
    size_t raw_sig_len;

    DSA_SIG *dsa_sig;

    if (sig == NULL || sig->raw_sig == NULL) {
        return NULL;
    }
    raw_sig_data = ssh_string_data(sig->raw_sig);
    if (raw_sig_data == NULL) {
        return NULL;
    }
    raw_sig_len = ssh_string_len(sig->raw_sig);

    dsa_sig = d2i_DSA_SIG(NULL, &raw_sig_data, raw_sig_len);
    if (dsa_sig == NULL) {
        return NULL;
    }

    DSA_SIG_get0(dsa_sig, &pr, &ps);
    if (pr == NULL || ps == NULL) {
        goto error;
    }

    r = ssh_make_bignum_string((BIGNUM *)pr);
    if (r == NULL) {
        goto error;
    }

    s = ssh_make_bignum_string((BIGNUM *)ps);
    if (s == NULL) {
        goto error;
    }

    r_len = ssh_string_len(r);
    r_offset_in  = (r_len > 20) ? (r_len - 20) : 0;
    r_offset_out = (r_len < 20) ? (20 - r_len) : 0;

    s_len = ssh_string_len(s);
    s_offset_in  = (s_len > 20) ? (s_len - 20) : 0;
    s_offset_out = (s_len < 20) ? (20 - s_len) : 0;

    memcpy(buffer + r_offset_out,
           ((char *)ssh_string_data(r)) + r_offset_in,
           r_len - r_offset_in);
    memcpy(buffer + 20 + s_offset_out,
           ((char *)ssh_string_data(s)) + s_offset_in,
           s_len - s_offset_in);

    DSA_SIG_free(dsa_sig);
    ssh_string_free(r);
    ssh_string_free(s);

    sig_blob = ssh_string_new(40);
    if (sig_blob == NULL) {
        return NULL;
    }

    ssh_string_fill(sig_blob, buffer, 40);

    return sig_blob;

error:
    DSA_SIG_free(dsa_sig);
    ssh_string_free(r);
    ssh_string_free(s);
    return NULL;
}

static ssh_string pki_ecdsa_signature_to_blob(const ssh_signature sig)
{
    ssh_string r = NULL;
    ssh_string s = NULL;

    ssh_buffer buf = NULL;
    ssh_string sig_blob = NULL;

    const BIGNUM *pr = NULL, *ps = NULL;

    const unsigned char *raw_sig_data = NULL;
    size_t raw_sig_len;

    ECDSA_SIG *ecdsa_sig;

    int rc;

    if (sig == NULL || sig->raw_sig == NULL) {
        return NULL;
    }
    raw_sig_data = ssh_string_data(sig->raw_sig);
    if (raw_sig_data == NULL) {
        return NULL;
    }
    raw_sig_len = ssh_string_len(sig->raw_sig);

    ecdsa_sig = d2i_ECDSA_SIG(NULL, &raw_sig_data, raw_sig_len);
    if (ecdsa_sig == NULL) {
        return NULL;
    }

    ECDSA_SIG_get0(ecdsa_sig, &pr, &ps);
    if (pr == NULL || ps == NULL) {
        goto error;
    }

    r = ssh_make_bignum_string((BIGNUM *)pr);
    if (r == NULL) {
        goto error;
    }

    s = ssh_make_bignum_string((BIGNUM *)ps);
    if (s == NULL) {
        goto error;
    }

    buf = ssh_buffer_new();
    if (buf == NULL) {
        goto error;
    }

    rc = ssh_buffer_add_ssh_string(buf, r);
    if (rc < 0) {
        goto error;
    }

    rc = ssh_buffer_add_ssh_string(buf, s);
    if (rc < 0) {
        goto error;
    }

    sig_blob = ssh_string_new(ssh_buffer_get_len(buf));
    if (sig_blob == NULL) {
        goto error;
    }

    ssh_string_fill(sig_blob, ssh_buffer_get(buf), ssh_buffer_get_len(buf));

    ssh_string_free(r);
    ssh_string_free(s);
    ECDSA_SIG_free(ecdsa_sig);
    ssh_buffer_free(buf);

    return sig_blob;

error:
    ssh_string_free(r);
    ssh_string_free(s);
    ECDSA_SIG_free(ecdsa_sig);
    ssh_buffer_free(buf);
    return NULL;
}

ssh_string pki_signature_to_blob(const ssh_signature sig)
{
    ssh_string sig_blob = NULL;

    switch(sig->type) {
        case SSH_KEYTYPE_DSS:
            sig_blob = pki_dsa_signature_to_blob(sig);
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sig_blob = ssh_string_copy(sig->raw_sig);
            break;
        case SSH_KEYTYPE_ED25519:
            sig_blob = pki_ed25519_sig_to_blob(sig);
            break;
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
#ifdef HAVE_OPENSSL_ECC
            sig_blob = pki_ecdsa_signature_to_blob(sig);
            break;
#endif
        default:
        case SSH_KEYTYPE_UNKNOWN:
            SSH_LOG(SSH_LOG_WARN, "Unknown signature key type: %s", sig->type_c);
            return NULL;
    }

    return sig_blob;
}

static int pki_signature_from_rsa_blob(const ssh_key pubkey,
                                       const ssh_string sig_blob,
                                       ssh_signature sig)
{
    uint32_t pad_len = 0;
    char *blob_orig;
    char *blob_padded_data;
    ssh_string sig_blob_padded;

    size_t rsalen = 0;
    size_t len = ssh_string_len(sig_blob);

    if (pubkey->rsa == NULL) {
        SSH_LOG(SSH_LOG_WARN, "Pubkey RSA field NULL");
        goto errout;
    }

    rsalen = RSA_size(pubkey->rsa);
    if (len > rsalen) {
        SSH_LOG(SSH_LOG_WARN,
                "Signature is too big: %lu > %lu",
                (unsigned long)len,
                (unsigned long)rsalen);
        goto errout;
    }

#ifdef DEBUG_CRYPTO
    SSH_LOG(SSH_LOG_WARN, "RSA signature len: %lu", (unsigned long)len);
    ssh_print_hexa("RSA signature", ssh_string_data(sig_blob), len);
#endif

    if (len == rsalen) {
        sig->raw_sig = ssh_string_copy(sig_blob);
    } else {
        /* pad the blob to the expected rsalen size */
        SSH_LOG(SSH_LOG_DEBUG,
                "RSA signature len %lu < %lu",
                (unsigned long)len,
                (unsigned long)rsalen);

        pad_len = rsalen - len;

        sig_blob_padded = ssh_string_new(rsalen);
        if (sig_blob_padded == NULL) {
            goto errout;
        }

        blob_padded_data = (char *) ssh_string_data(sig_blob_padded);
        blob_orig = (char *) ssh_string_data(sig_blob);

        /* front-pad the buffer with zeroes */
        explicit_bzero(blob_padded_data, pad_len);
        /* fill the rest with the actual signature blob */
        memcpy(blob_padded_data + pad_len, blob_orig, len);

        sig->raw_sig = sig_blob_padded;
    }

    return SSH_OK;

errout:
    return SSH_ERROR;
}

static int pki_signature_from_dsa_blob(UNUSED_PARAM(const ssh_key pubkey),
                                       const ssh_string sig_blob,
                                       ssh_signature sig)
{
    DSA_SIG *dsa_sig = NULL;
    BIGNUM *pr = NULL, *ps = NULL;

    ssh_string r;
    ssh_string s;

    size_t len;

    int raw_sig_len = 0;
    unsigned char *raw_sig_data = NULL;

    int rc;

    len = ssh_string_len(sig_blob);

    /* 40 is the dual signature blob len. */
    if (len != 40) {
        SSH_LOG(SSH_LOG_WARN,
                "Signature has wrong size: %lu",
                (unsigned long)len);
        goto error;
    }

#ifdef DEBUG_CRYPTO
    ssh_print_hexa("r", ssh_string_data(sig_blob), 20);
    ssh_print_hexa("s", (unsigned char *)ssh_string_data(sig_blob) + 20, 20);
#endif

    r = ssh_string_new(20);
    if (r == NULL) {
        goto error;
    }
    ssh_string_fill(r, ssh_string_data(sig_blob), 20);

    pr = ssh_make_string_bn(r);
    ssh_string_burn(r);
    ssh_string_free(r);
    if (pr == NULL) {
        goto error;
    }

    s = ssh_string_new(20);
    if (s == NULL) {
        goto error;
    }
    ssh_string_fill(s, (char *)ssh_string_data(sig_blob) + 20, 20);

    ps = ssh_make_string_bn(s);
    ssh_string_burn(s);
    ssh_string_free(s);
    if (ps == NULL) {
        goto error;
    }

    dsa_sig = DSA_SIG_new();
    if (dsa_sig == NULL) {
        goto error;
    }

    /* Memory management of pr and ps is transferred to DSA signature
     * object */
    rc = DSA_SIG_set0(dsa_sig, pr, ps);
    if (rc == 0) {
        goto error;
    }
    ps = NULL;
    pr = NULL;

    raw_sig_len = i2d_DSA_SIG(dsa_sig, &raw_sig_data);
    if (raw_sig_len < 0) {
        goto error;
    }

    sig->raw_sig = ssh_string_new(raw_sig_len);
    if (sig->raw_sig == NULL) {
        explicit_bzero(raw_sig_data, raw_sig_len);
        goto error;
    }

    rc = ssh_string_fill(sig->raw_sig, raw_sig_data, raw_sig_len);
    if (rc < 0) {
        explicit_bzero(raw_sig_data, raw_sig_len);
        goto error;
    }

    explicit_bzero(raw_sig_data, raw_sig_len);
    SAFE_FREE(raw_sig_data);
    DSA_SIG_free(dsa_sig);

    return SSH_OK;

error:
    bignum_safe_free(ps);
    bignum_safe_free(pr);
    SAFE_FREE(raw_sig_data);
    DSA_SIG_free(dsa_sig);
    return SSH_ERROR;
}

static int pki_signature_from_ecdsa_blob(UNUSED_PARAM(const ssh_key pubkey),
                                         const ssh_string sig_blob,
                                         ssh_signature sig)
{
    ECDSA_SIG *ecdsa_sig = NULL;
    BIGNUM *pr = NULL, *ps = NULL;

    ssh_string r;
    ssh_string s;

    ssh_buffer buf = NULL;
    uint32_t rlen;

    unsigned char *raw_sig_data = NULL;
    size_t raw_sig_len = 0;

    int rc;

    /* build ecdsa signature */
    buf = ssh_buffer_new();
    if (buf == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_buffer_add_data(buf,
                             ssh_string_data(sig_blob),
                             ssh_string_len(sig_blob));
    if (rc < 0) {
        goto error;
    }

    r = ssh_buffer_get_ssh_string(buf);
    if (r == NULL) {
        goto error;
    }

#ifdef DEBUG_CRYPTO
    ssh_print_hexa("r", ssh_string_data(r), ssh_string_len(r));
#endif

    pr = ssh_make_string_bn(r);
    ssh_string_burn(r);
    ssh_string_free(r);
    if (pr == NULL) {
        goto error;
    }

    s = ssh_buffer_get_ssh_string(buf);
    rlen = ssh_buffer_get_len(buf);
    SSH_BUFFER_FREE(buf);
    if (s == NULL) {
        goto error;
    }

    if (rlen != 0) {
        ssh_string_burn(s);
        ssh_string_free(s);
        SSH_LOG(SSH_LOG_WARN,
                "Signature has remaining bytes in inner "
                "sigblob: %lu",
                (unsigned long)rlen);
        goto error;
    }

#ifdef DEBUG_CRYPTO
    ssh_print_hexa("s", ssh_string_data(s), ssh_string_len(s));
#endif

    ps = ssh_make_string_bn(s);
    ssh_string_burn(s);
    ssh_string_free(s);
    if (ps == NULL) {
        goto error;
    }

    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL) {
        goto error;
    }

    /* Memory management of pr and ps is transferred to
     * ECDSA signature object */
    rc = ECDSA_SIG_set0(ecdsa_sig, pr, ps);
    if (rc == 0) {
        goto error;
    }
    pr = NULL;
    ps = NULL;

    rc = i2d_ECDSA_SIG(ecdsa_sig, &raw_sig_data);
    if (rc < 0) {
        goto error;
    }
    raw_sig_len = rc;

    sig->raw_sig = ssh_string_new(raw_sig_len);
    if (sig->raw_sig == NULL) {
        explicit_bzero(raw_sig_data, raw_sig_len);
        goto error;
    }

    rc = ssh_string_fill(sig->raw_sig, raw_sig_data, raw_sig_len);
    if (rc < 0) {
        explicit_bzero(raw_sig_data, raw_sig_len);
        goto error;
    }

    explicit_bzero(raw_sig_data, raw_sig_len);
    SAFE_FREE(raw_sig_data);
    ECDSA_SIG_free(ecdsa_sig);
    return SSH_OK;

error:
    SSH_BUFFER_FREE(buf);
    bignum_safe_free(ps);
    bignum_safe_free(pr);
    SAFE_FREE(raw_sig_data);
    if (ecdsa_sig != NULL) {
        ECDSA_SIG_free(ecdsa_sig);
    }
    return SSH_ERROR;
}

ssh_signature pki_signature_from_blob(const ssh_key pubkey,
                                      const ssh_string sig_blob,
                                      enum ssh_keytypes_e type,
                                      enum ssh_digest_e hash_type)
{
    ssh_signature sig;
    int rc;

    if (ssh_key_type_plain(pubkey->type) != type) {
        SSH_LOG(SSH_LOG_WARN,
                "Incompatible public key provided (%d) expecting (%d)",
                type,
                pubkey->type);
        return NULL;
    }

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }

    sig->type = type;
    sig->type_c = ssh_key_signature_to_char(type, hash_type);
    sig->hash_type = hash_type;

    switch(type) {
        case SSH_KEYTYPE_DSS:
            rc = pki_signature_from_dsa_blob(pubkey, sig_blob, sig);
            if (rc != SSH_OK) {
                goto error;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            rc = pki_signature_from_rsa_blob(pubkey, sig_blob, sig);
            if (rc != SSH_OK) {
                goto error;
            }
            break;
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_sig_from_blob(sig, sig_blob);
            if (rc != SSH_OK){
                goto error;
            }
            break;
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
        case SSH_KEYTYPE_ECDSA_P256_CERT01:
        case SSH_KEYTYPE_ECDSA_P384_CERT01:
        case SSH_KEYTYPE_ECDSA_P521_CERT01:
#ifdef HAVE_OPENSSL_ECC
            rc = pki_signature_from_ecdsa_blob(pubkey, sig_blob, sig);
            if (rc != SSH_OK) {
                goto error;
            }
            break;
#endif
        default:
        case SSH_KEYTYPE_UNKNOWN:
            SSH_LOG(SSH_LOG_WARN, "Unknown signature type");
            goto error;
    }

    return sig;

error:
    ssh_signature_free(sig);
    return NULL;
}

int pki_signature_verify(ssh_session session,
                         const ssh_signature sig,
                         const ssh_key key,
                         const unsigned char *input,
                         size_t input_len)
{
    int rc;

    if (session == NULL || sig == NULL || key == NULL || input == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Bad parameter provided to "
                               "pki_signature_verify()");
        return SSH_ERROR;
    }

    if (ssh_key_type_plain(key->type) != sig->type) {
        SSH_LOG(SSH_LOG_WARN,
                "Can not verify %s signature with %s key",
                sig->type_c,
                key->type_c);
        return SSH_ERROR;
    }

    /* Check if public key and hash type are compatible */
    rc = pki_key_check_hash_compatible(key, sig->hash_type);
    if (rc != SSH_OK) {
        return SSH_ERROR;
    }

    /* For ed25519 keys, verify using the input directly */
    if (key->type == SSH_KEYTYPE_ED25519 ||
        key->type == SSH_KEYTYPE_ED25519_CERT01)
    {
        rc = pki_ed25519_verify(key, sig, input, input_len);
    } else {
        /* For the other key types, calculate the hash and verify the signature */
        rc = pki_verify_data_signature(sig, key, input, input_len);
    }

    if (rc != SSH_OK){
        ssh_set_error(session,
                      SSH_FATAL,
                      "Signature verification error");
        return SSH_ERROR;
    }

    return SSH_OK;
}

static const EVP_MD *pki_digest_to_md(enum ssh_digest_e hash_type)
{
    const EVP_MD *md = NULL;

    switch (hash_type) {
    case SSH_DIGEST_SHA256:
        md = EVP_sha256();
        break;
    case SSH_DIGEST_SHA384:
        md = EVP_sha384();
        break;
    case SSH_DIGEST_SHA512:
        md = EVP_sha512();
        break;
    case SSH_DIGEST_SHA1:
        md = EVP_sha1();
        break;
    case SSH_DIGEST_AUTO:
    default:
        SSH_LOG(SSH_LOG_TRACE, "Unknown hash algorithm for type: %d",
                hash_type);
        return NULL;
    }

    return md;
}

static EVP_PKEY *pki_key_to_pkey(ssh_key key)
{
    EVP_PKEY *pkey = NULL;

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Out of memory");
        return NULL;
    }

    switch(key->type) {
    case SSH_KEYTYPE_DSS:
    case SSH_KEYTYPE_DSS_CERT01:
        if (key->dsa == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "NULL key->dsa");
            goto error;
        }
        EVP_PKEY_set1_DSA(pkey, key->dsa);
        break;
    case SSH_KEYTYPE_RSA:
    case SSH_KEYTYPE_RSA1:
    case SSH_KEYTYPE_RSA_CERT01:
        if (key->rsa == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "NULL key->rsa");
            goto error;
        }
        EVP_PKEY_set1_RSA(pkey, key->rsa);
        break;
    case SSH_KEYTYPE_ECDSA_P256:
    case SSH_KEYTYPE_ECDSA_P384:
    case SSH_KEYTYPE_ECDSA_P521:
    case SSH_KEYTYPE_ECDSA_P256_CERT01:
    case SSH_KEYTYPE_ECDSA_P384_CERT01:
    case SSH_KEYTYPE_ECDSA_P521_CERT01:
# if defined(HAVE_OPENSSL_ECC)
        if (key->ecdsa == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "NULL key->ecdsa");
            goto error;
        }
        EVP_PKEY_set1_EC_KEY(pkey, key->ecdsa);
        break;
# endif
    case SSH_KEYTYPE_ED25519:
        /* Not supported yet. This type requires the use of EVP_DigestSign*()
         * API and ECX keys. There is no EVP_set1_ECX_KEY() or equivalent yet. */
    case SSH_KEYTYPE_UNKNOWN:
    default:
        SSH_LOG(SSH_LOG_TRACE, "Unknown private key algorithm for type: %d",
                key->type);
        goto error;
    }

    return pkey;

error:
    EVP_PKEY_free(pkey);
    return NULL;
}

/**
 * @internal
 *
 * @brief Sign the given input data. The digest of to be signed is calculated
 * internally as necessary.
 *
 * @param[in]   privkey     The private key to be used for signing.
 * @param[in]   hash_type   The digest algorithm to be used.
 * @param[in]   input       The data to be signed.
 * @param[in]   input_len   The length of the data to be signed.
 *
 * @return  a newly allocated ssh_signature or NULL on error.
 */
ssh_signature pki_sign_data(const ssh_key privkey,
                            enum ssh_digest_e hash_type,
                            const unsigned char *input,
                            size_t input_len)
{
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    unsigned char *raw_sig_data = NULL;
    unsigned int raw_sig_len;

    ssh_signature sig = NULL;

    int rc;

    if (privkey == NULL || !ssh_key_is_private(privkey) || input == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Bad parameter provided to "
                               "pki_sign_data()");
        return NULL;
    }

    /* Check if public key and hash type are compatible */
    rc = pki_key_check_hash_compatible(privkey, hash_type);
    if (rc != SSH_OK) {
        return NULL;
    }

    /* Set hash algorithm to be used */
    md = pki_digest_to_md(hash_type);
    if (md == NULL) {
        return NULL;
    }

    /* Setup private key EVP_PKEY */
    pkey = pki_key_to_pkey(privkey);
    if (pkey == NULL) {
        return NULL;
    }

    /* Allocate buffer for signature */
    raw_sig_len = EVP_PKEY_size(pkey);
    raw_sig_data = (unsigned char *)malloc(raw_sig_len);
    if (raw_sig_data == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Out of memory");
        goto out;
    }

    /* Create the context */
    ctx = EVP_MD_CTX_create();
    if (ctx == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Out of memory");
        goto out;
    }

    /* Sign the data */
    rc = EVP_SignInit_ex(ctx, md, NULL);
    if (!rc){
        SSH_LOG(SSH_LOG_TRACE, "EVP_SignInit() failed");
        goto out;
    }

    rc = EVP_SignUpdate(ctx, input, input_len);
    if (!rc) {
        SSH_LOG(SSH_LOG_TRACE, "EVP_SignUpdate() failed");
        goto out;
    }

    rc = EVP_SignFinal(ctx, raw_sig_data, &raw_sig_len, pkey);
    if (!rc) {
        SSH_LOG(SSH_LOG_TRACE, "EVP_SignFinal() failed");
        goto out;
    }

#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Generated signature", raw_sig_data, raw_sig_len);
#endif

    /* Allocate and fill output signature */
    sig = ssh_signature_new();
    if (sig == NULL) {
        goto out;
    }

    sig->raw_sig = ssh_string_new(raw_sig_len);
    if (sig->raw_sig == NULL) {
        ssh_signature_free(sig);
        sig = NULL;
        goto out;
    }

    rc = ssh_string_fill(sig->raw_sig, raw_sig_data, raw_sig_len);
    if (rc < 0) {
        ssh_signature_free(sig);
        sig = NULL;
        goto out;
    }

    sig->type = privkey->type;
    sig->hash_type = hash_type;
    sig->type_c = ssh_key_signature_to_char(privkey->type, hash_type);

out:
    if (ctx != NULL) {
        EVP_MD_CTX_free(ctx);
    }
    if (raw_sig_data != NULL) {
        explicit_bzero(raw_sig_data, raw_sig_len);
    }
    SAFE_FREE(raw_sig_data);
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    return sig;
}

/**
 * @internal
 *
 * @brief Verify the signature of a given input. The digest of the input is
 * calculated internally as necessary.
 *
 * @param[in]   signature   The signature to be verified.
 * @param[in]   pubkey      The public key used to verify the signature.
 * @param[in]   input       The signed data.
 * @param[in]   input_len   The length of the signed data.
 *
 * @return  SSH_OK if the signature is valid; SSH_ERROR otherwise.
 */
int pki_verify_data_signature(ssh_signature signature,
                              const ssh_key pubkey,
                              const unsigned char *input,
                              size_t input_len)
{
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    unsigned char *raw_sig_data = NULL;
    unsigned int raw_sig_len;

    int rc = SSH_ERROR;
    int evp_rc;

    if (pubkey == NULL || ssh_key_is_private(pubkey) || input == NULL ||
        signature == NULL || signature->raw_sig == NULL)
    {
        SSH_LOG(SSH_LOG_TRACE, "Bad parameter provided to "
                               "pki_verify_data_signature()");
        return SSH_ERROR;
    }

    /* Check if public key and hash type are compatible */
    rc = pki_key_check_hash_compatible(pubkey, signature->hash_type);
    if (rc != SSH_OK) {
        return SSH_ERROR;
    }

    /* Get the signature to be verified */
    raw_sig_data = ssh_string_data(signature->raw_sig);
    raw_sig_len = ssh_string_len(signature->raw_sig);
    if (raw_sig_data == NULL) {
        return SSH_ERROR;
    }

    /* Set hash algorithm to be used */
    md = pki_digest_to_md(signature->hash_type);
    if (md == NULL) {
        return SSH_ERROR;
    }

    /* Setup public key EVP_PKEY */
    pkey = pki_key_to_pkey(pubkey);
    if (pkey == NULL) {
        return SSH_ERROR;
    }

    /* Create the context */
    ctx = EVP_MD_CTX_create();
    if (ctx == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Out of memory");
        goto out;
    }

    /* Verify the signature */
    evp_rc = EVP_VerifyInit_ex(ctx, md, NULL);
    if (!evp_rc){
        SSH_LOG(SSH_LOG_TRACE, "EVP_SignInit() failed");
        goto out;
    }

    evp_rc = EVP_VerifyUpdate(ctx, input, input_len);
    if (!evp_rc) {
        SSH_LOG(SSH_LOG_TRACE, "EVP_SignUpdate() failed");
        goto out;
    }

    evp_rc = EVP_VerifyFinal(ctx, raw_sig_data, raw_sig_len, pkey);
    if (evp_rc < 0) {
        SSH_LOG(SSH_LOG_TRACE, "EVP_SignFinal() failed");
        rc = SSH_ERROR;
    } else if (evp_rc == 0) {
        SSH_LOG(SSH_LOG_TRACE, "Signature invalid");
        rc = SSH_ERROR;
    } else if (evp_rc == 1) {
        SSH_LOG(SSH_LOG_TRACE, "Signature valid");
        rc = SSH_OK;
    }

out:
    if (ctx != NULL) {
        EVP_MD_CTX_free(ctx);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    return rc;
}

ssh_signature pki_do_sign_hash(const ssh_key privkey,
                               const unsigned char *hash,
                               size_t hlen,
                               enum ssh_digest_e hash_type)
{
    ssh_signature sig = NULL;
    int rc;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }

    sig->type = privkey->type;
    sig->type_c = ssh_key_signature_to_char(privkey->type, hash_type);
    sig->hash_type = hash_type;

    switch(privkey->type) {
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_sign(privkey, sig, hash, hlen);
            if (rc != SSH_OK) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        default:
            ssh_signature_free(sig);
            return NULL;
    }

    return sig;
}
#endif /* _PKI_CRYPTO_H */
