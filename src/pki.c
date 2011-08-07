/*
 * known_hosts.c
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

/**
 * @defgroup libssh_pki The SSH Public Key Infrastructure
 * @ingroup libssh
 *
 * Functions for the creation, importation and manipulation of public and
 * private keys in the context of the SSH protocol
 *
 * @{
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libssh/libssh.h"
#include "libssh/session.h"
#include "libssh/priv.h"
#include "libssh/pki.h"
#include "libssh/keys.h"
#include "libssh/buffer.h"

enum ssh_keytypes_e pki_privatekey_type_from_string(const char *privkey) {
    if (strncmp(privkey, DSA_HEADER_BEGIN, strlen(DSA_HEADER_BEGIN)) == 0) {
        return SSH_KEYTYPE_DSS;
    }

    if (strncmp(privkey, RSA_HEADER_BEGIN, strlen(RSA_HEADER_BEGIN)) == 0) {
        return SSH_KEYTYPE_RSA;
    }

    return SSH_KEYTYPE_UNKNOWN;
}

/**
 * @brief creates a new empty SSH key
 * @returns an empty ssh_key handle, or NULL on error.
 */
ssh_key ssh_key_new (void) {
  ssh_key ptr = malloc (sizeof (struct ssh_key_struct));
  if (ptr == NULL) {
      return NULL;
  }
  ZERO_STRUCTP(ptr);
  return ptr;
}

/**
 * @brief clean up the key and deallocate all existing keys
 * @param[in] key ssh_key to clean
 */
void ssh_key_clean (ssh_key key){
    if(key == NULL)
        return;
#ifdef HAVE_LIBGCRYPT
    if(key->dsa) gcry_sexp_release(key->dsa);
    if(key->rsa) gcry_sexp_release(key->rsa);
#elif defined HAVE_LIBCRYPTO
    if(key->dsa) DSA_free(key->dsa);
    if(key->rsa) RSA_free(key->rsa);
#endif
    key->flags=SSH_KEY_FLAG_EMPTY;
    key->type=SSH_KEYTYPE_UNKNOWN;
    key->type_c=NULL;
    key->dsa = NULL;
    key->rsa = NULL;
}

/**
 * @brief deallocate a SSH key
 * @param[in] key ssh_key handle to free
 */
void ssh_key_free (ssh_key key){
    if(key){
        ssh_key_clean(key);
        SAFE_FREE(key);
    }
}

/**
 * @brief returns the type of a ssh key
 * @param[in] key the ssh_key handle
 * @returns one of SSH_KEYTYPE_RSA,SSH_KEYTYPE_DSS,SSH_KEYTYPE_RSA1
 * @returns SSH_KEYTYPE_UNKNOWN if the type is unknown
 */
enum ssh_keytypes_e ssh_key_type(ssh_key key){
    if (key == NULL) {
        return SSH_KEYTYPE_UNKNOWN;
    }
    return key->type;
}

/**
 * @brief Convert a key type to a string.
 *
 * @param[in]  type     The type to convert.
 *
 * @return              A string for the keytype or NULL if unknown.
 */
const char *ssh_key_type_to_char(enum ssh_keytypes_e type) {
  switch (type) {
    case SSH_KEYTYPE_DSS:
      return "ssh-dss";
    case SSH_KEYTYPE_RSA:
      return "ssh-rsa";
    case SSH_KEYTYPE_RSA1:
      return "ssh-rsa1";
    case SSH_KEYTYPE_ECDSA:
      return "ssh-ecdsa";
    case SSH_KEYTYPE_UNKNOWN:
      return NULL;
  }

  /* We should never reach this */
  return NULL;
}

/**
 * @brief Convert a ssh key name to a ssh key type.
 *
 * @param[in] name      The name to convert.
 *
 * @return              The enum ssh key type.
 */
enum ssh_keytypes_e ssh_key_type_from_name(const char *name) {
  if (strcmp(name, "rsa1") == 0) {
    return SSH_KEYTYPE_RSA1;
  } else if (strcmp(name, "rsa") == 0) {
    return SSH_KEYTYPE_RSA;
  } else if (strcmp(name, "dsa") == 0) {
    return SSH_KEYTYPE_DSS;
  } else if (strcmp(name, "ssh-rsa1") == 0) {
    return SSH_KEYTYPE_RSA1;
  } else if (strcmp(name, "ssh-rsa") == 0) {
    return SSH_KEYTYPE_RSA;
  } else if (strcmp(name, "ssh-dss") == 0) {
    return SSH_KEYTYPE_DSS;
  } else if (strcmp(name, "ssh-ecdsa") == 0
             || strcmp(name, "ecdsa") == 0
             || strcmp(name, "ecdsa-sha2-nistp256") == 0
             || strcmp(name, "ecdsa-sha2-nistp384") == 0
             || strcmp(name, "ecdsa-sha2-nistp521") == 0) {
  }

  return SSH_KEYTYPE_UNKNOWN;
}

/**
 * @brief Check if the key has/is a public key.
 *
 * @param[in] k         The key to check.
 *
 * @return              1 if it is a public key, 0 if not.
 */
int ssh_key_is_public(ssh_key k) {
    if (k == NULL) {
        return 0;
    }

    return (k->flags & SSH_KEY_FLAG_PUBLIC);
}

/**
 * @brief Check if the key is a private key.
 *
 * @param[in] k         The key to check.
 *
 * @return              1 if it is a private key, 0 if not.
 */
int ssh_key_is_private(ssh_key k) {
    if (k == NULL) {
        return 0;
    }

    return (k->flags & SSH_KEY_FLAG_PRIVATE);
}

/**
 * @brief import a key from a file
 * @param[out]  key      the ssh_key to update
 * @param[in]  session  The SSH Session to use. If a key decryption callback is set, it will
 *                      be used to ask for the passphrase.
 * @param[in]  filename The filename of the the private key.
 * @param[in]  passphrase The passphrase to decrypt the private key. Set to null
 *                        if none is needed or it is unknown.
 * @returns SSH_OK on success, SSH_ERROR otherwise.
 **/
int ssh_key_import_private(ssh_session session,
                           const char *filename,
                           const char *passphrase,
                           ssh_key *pkey) {
    struct stat sb;
    char *key_buf;
    ssh_key key;
    FILE *file;
    off_t size;
    int rc;

    if (session == NULL || pkey == NULL) {
        return SSH_ERROR;
    }

    if (filename == NULL || *filename == '\0') {
        return SSH_ERROR;
    }

    rc = stat(filename, &sb);
    if (rc < 0) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                      "Error gettint stat of %s: %s",
                      filename, strerror(errno));
        return SSH_ERROR;
    }

    file = fopen(filename, "r");
    if (file == NULL) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                      "Error opening %s: %s",
                      filename, strerror(errno));
        return SSH_ERROR;
    }

    key_buf = malloc(sb.st_size + 1);
    if (key_buf == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    size = fread(key_buf, 1, sb.st_size, file);
    fclose(file);

    if (size != sb.st_size) {
        SAFE_FREE(key_buf);
        ssh_set_error(session, SSH_FATAL,
                      "Error reading %s: %s",
                      filename, strerror(errno));
        return SSH_ERROR;
    }

    key = pki_private_key_from_base64(session, key_buf, passphrase);
    SAFE_FREE(key_buf);
    if (key == NULL) {
        return SSH_ERROR;
    }

    *pkey = key;
    return SSH_OK;
}

/* temporary function to migrate seemlessly to ssh_key */
ssh_public_key ssh_pki_convert_key_to_publickey(ssh_key key) {
    ssh_public_key pub;

    if(key == NULL) {
        return NULL;
    }

    pub = malloc(sizeof(struct ssh_public_key_struct));
    if (pub == NULL) {
        return NULL;
    }
    ZERO_STRUCTP(pub);

    pub->dsa_pub = key->dsa;
    pub->rsa_pub = key->rsa;
    pub->type     = key->type;
    pub->type_c   = key->type_c;

    return pub;
}

/** @brief import a base64 formated key from a memory c-string
 *
 * @param   key     The key to fill, created with ssh_key_new()
 * @param   session The ssh session
 * @param   b64_key The c-string holding the base64 encoded key
 * @param   passphrase  The passphrase to decrypt the key, or NULL
 *
 * @return  SSH_ERROR in case of error, SSH_OK otherwise
 */
int ssh_pki_import_privkey_base64(ssh_session session,
                                  const char *b64_key,
                                  const char *passphrase,
                                  ssh_key *pkey) {
    ssh_key key;

    if (pkey == NULL || session == NULL) {
        return SSH_ERROR;
    }

    if (b64_key == NULL || !*b64_key) {
        return SSH_ERROR;
    }

    ssh_log(session, SSH_LOG_RARE, "Trying to decode privkey passphrase=%s",
            passphrase ? "true" : "false");

    key = pki_private_key_from_base64(session, b64_key, passphrase);
    if (key == NULL) {
        return SSH_ERROR;
    }

    *pkey = key;

    return SSH_OK;
}

ssh_key ssh_pki_publickey_from_privatekey(ssh_key privkey) {
    return pki_publickey_from_privatekey(privkey);
}

/*
 * This function signs the session id (known as H) as a string then
 * the content of sigbuf */
ssh_string ssh_pki_do_sign(ssh_session session, ssh_buffer sigbuf,
    ssh_key privatekey) {
  struct ssh_crypto_struct *crypto = session->current_crypto ? session->current_crypto :
    session->next_crypto;
  unsigned char hash[SHA_DIGEST_LEN + 1] = {0};
  ssh_string session_str = NULL;
  ssh_string signature = NULL;
  SIGNATURE *sign = NULL;
  SHACTX ctx = NULL;
#ifdef HAVE_LIBGCRYPT
  gcry_sexp_t gcryhash;
#endif

  if(privatekey == NULL || !ssh_key_is_private(privatekey)) {
      return NULL;
  }

  session_str = ssh_string_new(SHA_DIGEST_LEN);
  if (session_str == NULL) {
    return NULL;
  }
  ssh_string_fill(session_str, crypto->session_id, SHA_DIGEST_LEN);

  ctx = sha1_init();
  if (ctx == NULL) {
    ssh_string_free(session_str);
    return NULL;
  }

  sha1_update(ctx, session_str, ssh_string_len(session_str) + 4);
  ssh_string_free(session_str);
  sha1_update(ctx, buffer_get_rest(sigbuf), buffer_get_rest_len(sigbuf));
  sha1_final(hash + 1,ctx);
  hash[0] = 0;

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("Hash being signed with dsa", hash + 1, SHA_DIGEST_LEN);
#endif

  sign = malloc(sizeof(SIGNATURE));
  if (sign == NULL) {
    return NULL;
  }

  switch(privatekey->type) {
    case SSH_KEYTYPE_DSS:
#ifdef HAVE_LIBGCRYPT
      if (gcry_sexp_build(&gcryhash, NULL, "%b", SHA_DIGEST_LEN + 1, hash) ||
          gcry_pk_sign(&sign->dsa_sign, gcryhash, privatekey->dsa)) {
        ssh_set_error(session, SSH_FATAL, "Signing: libcrypt error");
        gcry_sexp_release(gcryhash);
        signature_free(sign);
        return NULL;
      }
#elif defined HAVE_LIBCRYPTO
      sign->dsa_sign = DSA_do_sign(hash + 1, SHA_DIGEST_LEN,
          privatekey->dsa);
      if (sign->dsa_sign == NULL) {
        ssh_set_error(session, SSH_FATAL, "Signing: openssl error");
        signature_free(sign);
        return NULL;
      }
#ifdef DEBUG_CRYPTO
      ssh_print_bignum("r", sign->dsa_sign->r);
      ssh_print_bignum("s", sign->dsa_sign->s);
#endif
#endif /* HAVE_LIBCRYPTO */
      sign->rsa_sign = NULL;
      break;
    case SSH_KEYTYPE_RSA:
#ifdef HAVE_LIBGCRYPT
      if (gcry_sexp_build(&gcryhash, NULL, "(data(flags pkcs1)(hash sha1 %b))",
            SHA_DIGEST_LEN, hash + 1) ||
          gcry_pk_sign(&sign->rsa_sign, gcryhash, privatekey->rsa)) {
        ssh_set_error(session, SSH_FATAL, "Signing: libcrypt error");
        gcry_sexp_release(gcryhash);
        signature_free(sign);
        return NULL;
      }
#elif defined HAVE_LIBCRYPTO
      sign->rsa_sign = RSA_do_sign(hash + 1, SHA_DIGEST_LEN,
          privatekey->rsa);
      if (sign->rsa_sign == NULL) {
        ssh_set_error(session, SSH_FATAL, "Signing: openssl error");
        signature_free(sign);
        return NULL;
      }
#endif
      sign->dsa_sign = NULL;
      break;
    default:
      signature_free(sign);
      return NULL;
  }
#ifdef HAVE_LIBGCRYPT
  gcry_sexp_release(gcryhash);
#endif

  sign->type = privatekey->type;

  signature = signature_to_string(sign);
  signature_free(sign);

  return signature;
}


/**
 * @}
 */
