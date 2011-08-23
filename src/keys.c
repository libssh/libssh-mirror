/*
 * keys.c - decoding a public key or signature and verifying them
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2005 by Aris Adamantiadis
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

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_LIBCRYPTO
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#endif
#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/server.h"
#include "libssh/buffer.h"
#include "libssh/agent.h"
#include "libssh/session.h"
#include "libssh/keys.h"
#include "libssh/dh.h"
#include "libssh/messages.h"
#include "libssh/string.h"

/**
 * @addtogroup libssh_auth
 *
 * @{
 */

void publickey_free(ssh_public_key key) {
  if (key == NULL) {
    return;
  }

  switch(key->type) {
    case SSH_KEYTYPE_DSS:
#ifdef HAVE_LIBGCRYPT
      gcry_sexp_release(key->dsa_pub);
#elif HAVE_LIBCRYPTO
      DSA_free(key->dsa_pub);
#endif
      break;
    case SSH_KEYTYPE_RSA:
    case SSH_KEYTYPE_RSA1:
#ifdef HAVE_LIBGCRYPT
      gcry_sexp_release(key->rsa_pub);
#elif defined HAVE_LIBCRYPTO
      RSA_free(key->rsa_pub);
#endif
      break;
    default:
      break;
  }
  SAFE_FREE(key);
}

/**
 * @brief Make a public_key object out of a private_key object.
 *
 * @param[in]  prv      The private key to generate the public key.
 *
 * @returns             The generated public key, NULL on error.
 *
 * @see publickey_to_string()
 */
ssh_public_key publickey_from_privatekey(ssh_private_key prv) {
  ssh_public_key key = NULL;
#ifdef HAVE_LIBGCRYPT
  gcry_sexp_t sexp;
  const char *tmp = NULL;
  size_t size;
  ssh_string p = NULL;
  ssh_string q = NULL;
  ssh_string g = NULL;
  ssh_string y = NULL;
  ssh_string e = NULL;
  ssh_string n = NULL;
#endif /* HAVE_LIBGCRYPT */

  key = malloc(sizeof(struct ssh_public_key_struct));
  if (key == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(key);
  key->type = prv->type;
  switch(key->type) {
    case SSH_KEYTYPE_DSS:
#ifdef HAVE_LIBGCRYPT
      sexp = gcry_sexp_find_token(prv->dsa_priv, "p", 0);
      if (sexp == NULL) {
        goto error;
      }
      tmp = gcry_sexp_nth_data(sexp, 1, &size);
      p = ssh_string_new(size);
      if (p == NULL) {
        goto error;
      }
      ssh_string_fill(p,(char *) tmp, size);
      gcry_sexp_release(sexp);

      sexp = gcry_sexp_find_token(prv->dsa_priv,"q",0);
      if (sexp == NULL) {
        goto error;
      }
      tmp = gcry_sexp_nth_data(sexp,1,&size);
      q = ssh_string_new(size);
      if (q == NULL) {
        goto error;
      }
      ssh_string_fill(q,(char *) tmp,size);
      gcry_sexp_release(sexp);

      sexp = gcry_sexp_find_token(prv->dsa_priv, "g", 0);
      if (sexp == NULL) {
        goto error;
      }
      tmp = gcry_sexp_nth_data(sexp,1,&size);
      g = ssh_string_new(size);
      if (g == NULL) {
        goto error;
      }
      ssh_string_fill(g,(char *) tmp,size);
      gcry_sexp_release(sexp);

      sexp = gcry_sexp_find_token(prv->dsa_priv,"y",0);
      if (sexp == NULL) {
        goto error;
      }
      tmp = gcry_sexp_nth_data(sexp,1,&size);
      y = ssh_string_new(size);
      if (y == NULL) {
        goto error;
      }
      ssh_string_fill(y,(char *) tmp,size);
      gcry_sexp_release(sexp);

      gcry_sexp_build(&key->dsa_pub, NULL,
          "(public-key(dsa(p %b)(q %b)(g %b)(y %b)))",
          ssh_string_len(p), ssh_string_data(p),
          ssh_string_len(q), ssh_string_data(q),
          ssh_string_len(g), ssh_string_data(g),
          ssh_string_len(y), ssh_string_data(y));

      ssh_string_burn(p);
      ssh_string_free(p);
      ssh_string_burn(q);
      ssh_string_free(q);
      ssh_string_burn(g);
      ssh_string_free(g);
      ssh_string_burn(y);
      ssh_string_free(y);
#elif defined HAVE_LIBCRYPTO
      key->dsa_pub = DSA_new();
      if (key->dsa_pub == NULL) {
        goto error;
      }
      key->dsa_pub->p = BN_dup(prv->dsa_priv->p);
      key->dsa_pub->q = BN_dup(prv->dsa_priv->q);
      key->dsa_pub->g = BN_dup(prv->dsa_priv->g);
      key->dsa_pub->pub_key = BN_dup(prv->dsa_priv->pub_key);
      if (key->dsa_pub->p == NULL ||
          key->dsa_pub->q == NULL ||
          key->dsa_pub->g == NULL ||
          key->dsa_pub->pub_key == NULL) {
        goto error;
      }
#endif /* HAVE_LIBCRYPTO */
      break;
    case SSH_KEYTYPE_RSA:
    case SSH_KEYTYPE_RSA1:
#ifdef HAVE_LIBGCRYPT
      sexp = gcry_sexp_find_token(prv->rsa_priv, "n", 0);
      if (sexp == NULL) {
        goto error;
      }
      tmp = gcry_sexp_nth_data(sexp, 1, &size);
      n = ssh_string_new(size);
      if (n == NULL) {
        goto error;
      }
      ssh_string_fill(n, (char *) tmp, size);
      gcry_sexp_release(sexp);

      sexp = gcry_sexp_find_token(prv->rsa_priv, "e", 0);
      if (sexp == NULL) {
        goto error;
      }
      tmp = gcry_sexp_nth_data(sexp, 1, &size);
      e = ssh_string_new(size);
      if (e == NULL) {
        goto error;
      }
      ssh_string_fill(e, (char *) tmp, size);
      gcry_sexp_release(sexp);

      gcry_sexp_build(&key->rsa_pub, NULL,
          "(public-key(rsa(n %b)(e %b)))",
          ssh_string_len(n), ssh_string_data(n),
          ssh_string_len(e), ssh_string_data(e));
      if (key->rsa_pub == NULL) {
        goto error;
      }

      ssh_string_burn(e);
      ssh_string_free(e);
      ssh_string_burn(n);
      ssh_string_free(n);
#elif defined HAVE_LIBCRYPTO
      key->rsa_pub = RSA_new();
      if (key->rsa_pub == NULL) {
        goto error;
      }
      key->rsa_pub->e = BN_dup(prv->rsa_priv->e);
      key->rsa_pub->n = BN_dup(prv->rsa_priv->n);
      if (key->rsa_pub->e == NULL ||
          key->rsa_pub->n == NULL) {
        goto error;
      }
#endif
      break;
    default:
    	publickey_free(key);
    	return NULL;
  }
  key->type_c = ssh_type_to_char(prv->type);

  return key;
error:
#ifdef HAVE_LIBGCRYPT
  gcry_sexp_release(sexp);
  ssh_string_burn(p);
  ssh_string_free(p);
  ssh_string_burn(q);
  ssh_string_free(q);
  ssh_string_burn(g);
  ssh_string_free(g);
  ssh_string_burn(y);
  ssh_string_free(y);

  ssh_string_burn(e);
  ssh_string_free(e);
  ssh_string_burn(n);
  ssh_string_free(n);
#endif
  publickey_free(key);

  return NULL;
}

void signature_free(SIGNATURE *sign) {
  if (sign == NULL) {
    return;
  }

  switch(sign->type) {
    case SSH_KEYTYPE_DSS:
#ifdef HAVE_LIBGCRYPT
      gcry_sexp_release(sign->dsa_sign);
#elif defined HAVE_LIBCRYPTO
      DSA_SIG_free(sign->dsa_sign);
#endif
      break;
    case SSH_KEYTYPE_RSA:
    case SSH_KEYTYPE_RSA1:
#ifdef HAVE_LIBGCRYPT
      gcry_sexp_release(sign->rsa_sign);
#elif defined HAVE_LIBCRYPTO
      SAFE_FREE(sign->rsa_sign);
#endif
      break;
    default:
      /* FIXME Passing NULL segfaults */
#if 0
       ssh_log(NULL, SSH_LOG_RARE, "Freeing a signature with no type!\n"); */
#endif
         break;
    }
  SAFE_FREE(sign);
}

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
