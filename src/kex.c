/*
 * kex.c - key exchange
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/dh.h"
#include "libssh/kex.h"
#include "libssh/session.h"
#include "libssh/ssh2.h"
#include "libssh/string.h"
#include "libssh/curve25519.h"
#include "libssh/knownhosts.h"
#include "libssh/misc.h"

#ifdef HAVE_LIBGCRYPT
# define BLOWFISH "blowfish-cbc,"
# define AES "aes256-gcm@openssh.com,aes128-gcm@openssh.com," \
             "aes256-ctr,aes192-ctr,aes128-ctr," \
             "aes256-cbc,aes192-cbc,aes128-cbc,"
# define DES "3des-cbc"
# define DES_SUPPORTED "3des-cbc"

#elif defined HAVE_LIBMBEDCRYPTO
# define BLOWFISH "blowfish-cbc,"
# ifdef MBEDTLS_GCM_C
#  define GCM "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
# else
#  define GCM ""
# endif /* MBEDTLS_GCM_C */
# define AES GCM "aes256-ctr,aes192-ctr,aes128-ctr," \
             "aes256-cbc,aes192-cbc,aes128-cbc,"
# define DES "3des-cbc"
# define DES_SUPPORTED "3des-cbc"

#elif defined(HAVE_LIBCRYPTO)

# ifdef HAVE_OPENSSL_BLOWFISH_H
#  define BLOWFISH "blowfish-cbc,"
# else /* HAVE_OPENSSL_BLOWFISH_H */
#  define BLOWFISH ""
# endif /* HAVE_OPENSSL_BLOWFISH_H */

# ifdef HAVE_OPENSSL_AES_H
#  ifdef HAVE_OPENSSL_EVP_AES_GCM
#   define GCM "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
#  else
#   define GCM ""
#  endif /* HAVE_OPENSSL_EVP_AES_GCM */
#  ifdef BROKEN_AES_CTR
#   define AES GCM "aes256-cbc,aes192-cbc,aes128-cbc,"
#  else /* BROKEN_AES_CTR */
#   define AES GCM "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,"
#  endif /* BROKEN_AES_CTR */
# else /* HAVE_OPENSSL_AES_H */
#  define AES ""
# endif /* HAVE_OPENSSL_AES_H */

# define DES "3des-cbc"
# define DES_SUPPORTED "3des-cbc"
#endif /* HAVE_LIBCRYPTO */

#ifdef WITH_ZLIB
#define ZLIB "none,zlib,zlib@openssh.com"
#else
#define ZLIB "none"
#endif

#ifdef HAVE_CURVE25519
#define CURVE25519 "curve25519-sha256,curve25519-sha256@libssh.org,"
#else
#define CURVE25519 ""
#endif

#ifdef HAVE_ECDH
#define ECDH "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
#define PUBLIC_KEY_ALGORITHMS "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,rsa-sha2-512,rsa-sha2-256,ssh-dss"
#else
#ifdef HAVE_DSA
#define PUBLIC_KEY_ALGORITHMS "ssh-ed25519,ssh-rsa,rsa-sha2-512,rsa-sha2-256,ssh-dss"
#else
#define PUBLIC_KEY_ALGORITHMS "ssh-ed25519,ssh-rsa,rsa-sha2-512,rsa-sha2-256"
#endif
#define ECDH ""
#endif

#define CHACHA20 "chacha20-poly1305@openssh.com,"

#define KEY_EXCHANGE CURVE25519 ECDH "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
#define KEX_METHODS_SIZE 10

/* RFC 8308 */
#define KEX_EXTENSION_CLIENT "ext-info-c"

/* NOTE: This is a fixed API and the index is defined by ssh_kex_types_e */
static const char *default_methods[] = {
  KEY_EXCHANGE,
  PUBLIC_KEY_ALGORITHMS,
  AES BLOWFISH DES,
  AES BLOWFISH DES,
  "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  "none",
  "none",
  "",
  "",
  NULL
};

/* NOTE: This is a fixed API and the index is defined by ssh_kex_types_e */
static const char *supported_methods[] = {
  KEY_EXCHANGE,
  PUBLIC_KEY_ALGORITHMS,
  CHACHA20 AES BLOWFISH DES_SUPPORTED,
  CHACHA20 AES BLOWFISH DES_SUPPORTED,
  "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  ZLIB,
  ZLIB,
  "",
  "",
  NULL
};

/* descriptions of the key exchange packet */
static const char *ssh_kex_descriptions[] = {
  "kex algos",
  "server host key algo",
  "encryption client->server",
  "encryption server->client",
  "mac algo client->server",
  "mac algo server->client",
  "compression algo client->server",
  "compression algo server->client",
  "languages client->server",
  "languages server->client",
  NULL
};

/* tokenize will return a token of strings delimited by ",". the first element has to be freed */
static char **tokenize(const char *chain){
    char **tokens;
    size_t n=1;
    size_t i=0;
    char *tmp;
    char *ptr;

    tmp = strdup(chain);
    if (tmp == NULL) {
      return NULL;
    }
    ptr = tmp;
    while(*ptr){
        if(*ptr==','){
            n++;
            *ptr=0;
        }
        ptr++;
    }
    /* now n contains the number of tokens, the first possibly empty if the list was empty too e.g. "" */
    tokens = calloc(n + 1, sizeof(char *)); /* +1 for the null */
    if (tokens == NULL) {
      SAFE_FREE(tmp);
      return NULL;
    }
    ptr=tmp;
    for(i=0;i<n;i++){
        tokens[i]=ptr;
        while(*ptr)
            ptr++; // find a zero
        ptr++; // then go one step further
    }
    tokens[i]=NULL;
    return tokens;
}

/* same as tokenize(), but with spaces instead of ',' */
/* TODO FIXME rewrite me! */
char **ssh_space_tokenize(const char *chain){
    char **tokens;
    size_t n=1;
    size_t i=0;
    char *tmp;
    char *ptr;

    tmp = strdup(chain);
    if (tmp == NULL) {
      return NULL;
    }
    ptr = tmp;

    while(*ptr==' ')
        ++ptr; /* skip initial spaces */
    while(*ptr){
        if(*ptr==' '){
            n++; /* count one token per word */
            *ptr=0;
            while(*(ptr+1)==' '){ /* don't count if the tokens have more than 2 spaces */
                *(ptr++)=0;
            }
        }
        ptr++;
    }
    /* now n contains the number of tokens, the first possibly empty if the list was empty too e.g. "" */
    tokens = calloc(n + 1, sizeof(char *)); /* +1 for the null */
    if (tokens == NULL) {
      SAFE_FREE(tmp);
      return NULL;
    }
    ptr=tmp; /* we don't pass the initial spaces because the "tmp" pointer is needed by the caller */
                    /* function to free the tokens. */
    for(i=0;i<n;i++){
        tokens[i]=ptr;
        if(i!=n-1){
            while(*ptr)
                ptr++; // find a zero
            while(!*(ptr+1))
                ++ptr; /* if the zero is followed by other zeros, go through them */
            ptr++; // then go one step further
        }
    }
    tokens[i]=NULL;
    return tokens;
}

const char *ssh_kex_get_default_methods(uint32_t algo)
{
    if (algo >= KEX_METHODS_SIZE) {
        return NULL;
    }

    return default_methods[algo];
}

const char *ssh_kex_get_supported_method(uint32_t algo) {
  if (algo >= KEX_METHODS_SIZE) {
    return NULL;
  }

  return supported_methods[algo];
}

const char *ssh_kex_get_description(uint32_t algo) {
  if (algo >= KEX_METHODS_SIZE) {
    return NULL;
  }

  return ssh_kex_descriptions[algo];
}

/* find_matching gets 2 parameters : a list of available objects (available_d), separated by colons,*/
/* and a list of preferred objects (preferred_d) */
/* it will return a strduped pointer on the first preferred object found in the available objects list */

char *ssh_find_matching(const char *available_d, const char *preferred_d){
    char ** tok_available, **tok_preferred;
    int i_avail, i_pref;
    char *ret;

    if ((available_d == NULL) || (preferred_d == NULL)) {
      return NULL; /* don't deal with null args */
    }

    tok_available = tokenize(available_d);
    if (tok_available == NULL) {
      return NULL;
    }

    tok_preferred = tokenize(preferred_d);
    if (tok_preferred == NULL) {
      SAFE_FREE(tok_available[0]);
      SAFE_FREE(tok_available);
      return NULL;
    }

    for(i_pref=0; tok_preferred[i_pref] ; ++i_pref){
      for(i_avail=0; tok_available[i_avail]; ++i_avail){
        if(strcmp(tok_available[i_avail],tok_preferred[i_pref]) == 0){
          /* match */
          ret=strdup(tok_available[i_avail]);
          /* free the tokens */
          SAFE_FREE(tok_available[0]);
          SAFE_FREE(tok_preferred[0]);
          SAFE_FREE(tok_available);
          SAFE_FREE(tok_preferred);
          return ret;
        }
      }
    }
    SAFE_FREE(tok_available[0]);
    SAFE_FREE(tok_preferred[0]);
    SAFE_FREE(tok_available);
    SAFE_FREE(tok_preferred);
    return NULL;
}

static char *ssh_find_all_matching(const char *available_d,
                                   const char *preferred_d)
{
    char **tok_available, **tok_preferred;
    int i_avail, i_pref;
    char *ret;
    unsigned max, len, pos = 0;

    if ((available_d == NULL) || (preferred_d == NULL)) {
        return NULL; /* don't deal with null args */
    }

    max = MAX(strlen(available_d), strlen(preferred_d));

    ret = malloc(max+1);
    if (ret == NULL) {
      return NULL;
    }
    ret[0] = 0;

    tok_available = tokenize(available_d);
    if (tok_available == NULL) {
        SAFE_FREE(ret);
        return NULL;
    }

    tok_preferred = tokenize(preferred_d);
    if (tok_preferred == NULL) {
        SAFE_FREE(ret);
        SAFE_FREE(tok_available[0]);
        SAFE_FREE(tok_available);
        return NULL;
    }

    for (i_pref = 0; tok_preferred[i_pref] ; ++i_pref) {
        for (i_avail = 0; tok_available[i_avail]; ++i_avail) {
            int cmp = strcmp(tok_available[i_avail],tok_preferred[i_pref]);
            if (cmp == 0) {
                /* match */
                if (pos != 0) {
                    ret[pos] = ',';
                    pos++;
                }

                len = strlen(tok_available[i_avail]);
                memcpy(&ret[pos], tok_available[i_avail], len);
                pos += len;
                ret[pos] = '\0';
            }
        }
    }

    if (ret[0] == '\0') {
        SAFE_FREE(ret);
        ret = NULL;
    }

    SAFE_FREE(tok_available[0]);
    SAFE_FREE(tok_preferred[0]);
    SAFE_FREE(tok_available);
    SAFE_FREE(tok_preferred);

    return ret;
}

/**
 * @internal
 * @brief returns whether the first client key exchange algorithm or
 *        hostkey type matches its server counterpart
 * @returns whether the first client key exchange algorithm or hostkey type
 *          matches its server counterpart
 */
static int cmp_first_kex_algo(const char *client_str,
                              const char *server_str) {
    int is_wrong = 1;
    char **server_str_tokens = NULL;
    char **client_str_tokens = NULL;

    if ((client_str == NULL) || (server_str == NULL)) {
        goto out;
    }

    client_str_tokens = tokenize(client_str);

    if (client_str_tokens == NULL) {
        goto out;
    }

    if (client_str_tokens[0] == NULL) {
        goto freeout;
    }

    server_str_tokens = tokenize(server_str);
    if (server_str_tokens == NULL) {
        goto freeout;
    }

    is_wrong = (strcmp(client_str_tokens[0], server_str_tokens[0]) != 0);

    SAFE_FREE(server_str_tokens[0]);
    SAFE_FREE(server_str_tokens);
freeout:
    SAFE_FREE(client_str_tokens[0]);
    SAFE_FREE(client_str_tokens);
out:
    return is_wrong;
}

SSH_PACKET_CALLBACK(ssh_packet_kexinit){
    int i, ok;
    int server_kex=session->server;
    ssh_string str = NULL;
    char *strings[KEX_METHODS_SIZE] = {0};
    int rc = SSH_ERROR;

    uint8_t first_kex_packet_follows = 0;
    uint32_t kexinit_reserved = 0;

    (void)type;
    (void)user;

    if (session->session_state == SSH_SESSION_STATE_AUTHENTICATED){
        SSH_LOG(SSH_LOG_WARNING, "Other side initiating key re-exchange");
    } else if(session->session_state != SSH_SESSION_STATE_INITIAL_KEX){
        ssh_set_error(session,SSH_FATAL,"SSH_KEXINIT received in wrong state");
        goto error;
    }

    if (server_kex) {
        rc = ssh_buffer_get_data(packet,session->next_crypto->client_kex.cookie, 16);
        if (rc != 16) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: no cookie in packet");
            goto error;
        }

        rc = ssh_hashbufin_add_cookie(session, session->next_crypto->client_kex.cookie);
        if (rc < 0) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: adding cookie failed");
            goto error;
        }
    } else {
        rc = ssh_buffer_get_data(packet,session->next_crypto->server_kex.cookie, 16);
        if (rc != 16) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: no cookie in packet");
            goto error;
        }

        rc = ssh_hashbufin_add_cookie(session, session->next_crypto->server_kex.cookie);
        if (rc < 0) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: adding cookie failed");
            goto error;
        }
    }

    for (i = 0; i < KEX_METHODS_SIZE; i++) {
        str = ssh_buffer_get_ssh_string(packet);
        if (str == NULL) {
          goto error;
        }

        rc = ssh_buffer_add_ssh_string(session->in_hashbuf, str);
        if (rc < 0) {
            ssh_set_error(session, SSH_FATAL, "Error adding string in hash buffer");
            goto error;
        }

        strings[i] = ssh_string_to_char(str);
        if (strings[i] == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        ssh_string_free(str);
        str = NULL;
    }

    /* copy the server kex info into an array of strings */
    if (server_kex) {
        for (i = 0; i < SSH_KEX_METHODS; i++) {
            session->next_crypto->client_kex.methods[i] = strings[i];
        }
    } else { /* client */
        for (i = 0; i < SSH_KEX_METHODS; i++) {
            session->next_crypto->server_kex.methods[i] = strings[i];
        }
    }

    /*
     * Handle the two final fields for the KEXINIT message (RFC 4253 7.1):
     *
     *      boolean      first_kex_packet_follows
     *      uint32       0 (reserved for future extension)
     *
     * Notably if clients set 'first_kex_packet_follows', it is expected
     * that its value is included when computing the session ID (see
     * 'make_sessionid').
     */
    if (server_kex) {
        rc = ssh_buffer_get_u8(packet, &first_kex_packet_follows);
        if (rc != 1) {
            goto error;
        }

        rc = ssh_buffer_add_u8(session->in_hashbuf, first_kex_packet_follows);
        if (rc < 0) {
            goto error;
        }

        rc = ssh_buffer_add_u32(session->in_hashbuf, kexinit_reserved);
        if (rc < 0) {
            goto error;
        }

        /*
         * If client sent a ext-info-c message in the kex list, it supports
         * RFC 8308 extension negotiation.
         */
        ok = ssh_match_group(session->next_crypto->client_kex.methods[SSH_KEX],
                             KEX_EXTENSION_CLIENT);
        if (ok) {
            /*
             * Enable all the supported extensions and when the time comes
             * (after NEWKEYS) send them to the client.
             */
            SSH_LOG(SSH_LOG_DEBUG, "The client supports extension "
                    "negotiation: enabling all extensions");
            session->extensions = SSH_EXT_ALL;
        }

        /*
         * Remember whether 'first_kex_packet_follows' was set and the client
         * guess was wrong: in this case the next SSH_MSG_KEXDH_INIT message
         * must be ignored.
         */
        if (first_kex_packet_follows) {
          session->first_kex_follows_guess_wrong =
            cmp_first_kex_algo(session->next_crypto->client_kex.methods[SSH_KEX],
                               session->next_crypto->server_kex.methods[SSH_KEX]) ||
            cmp_first_kex_algo(session->next_crypto->client_kex.methods[SSH_HOSTKEYS],
                               session->next_crypto->server_kex.methods[SSH_HOSTKEYS]);
        }
    }

    session->session_state = SSH_SESSION_STATE_KEXINIT_RECEIVED;
    session->dh_handshake_state = DH_STATE_INIT;
    session->ssh_connection_callback(session);
    return SSH_PACKET_USED;

error:
    ssh_string_free(str);
    for (i = 0; i < SSH_KEX_METHODS; i++) {
        if (server_kex) {
            session->next_crypto->client_kex.methods[i] = NULL;
        } else { /* client */
            session->next_crypto->server_kex.methods[i] = NULL;
        }
        SAFE_FREE(strings[i]);
    }

    session->session_state = SSH_SESSION_STATE_ERROR;

    return SSH_PACKET_USED;
}

void ssh_list_kex(struct ssh_kex_struct *kex) {
  int i = 0;

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("session cookie", kex->cookie, 16);
#endif

  for(i = 0; i < SSH_KEX_METHODS; i++) {
    if (kex->methods[i] == NULL) {
      continue;
    }
    SSH_LOG(SSH_LOG_FUNCTIONS, "%s: %s",
        ssh_kex_descriptions[i], kex->methods[i]);
  }
}

/**
 * @internal
 * @brief selects the hostkey mechanisms to be chosen for the key exchange,
 * as some hostkey mechanisms may be present in known_hosts file and preferred
 * @returns a cstring containing a comma-separated list of hostkey methods.
 *          NULL if no method matches
 */
char *ssh_client_select_hostkeys(ssh_session session)
{
    char methods_buffer[128]={0};
    char tail_buffer[128]={0};
    char *new_hostkeys = NULL;
    static const char *preferred_hostkeys[] = {
        "ssh-ed25519",
        "ecdsa-sha2-nistp521",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp256",
        "ssh-rsa",
#ifdef HAVE_DSA
        "ssh-dss",
#endif
        NULL
    };
    struct ssh_list *algo_list = NULL;
    struct ssh_iterator *it = NULL;
    size_t algo_count;
    int needcomma = 0;
    size_t i, len;

    algo_list = ssh_known_hosts_get_algorithms(session);
    if (algo_list == NULL) {
        return NULL;
    }

    algo_count = ssh_list_count(algo_list);
    if (algo_count == 0) {
        ssh_list_free(algo_list);
        return NULL;
    }

    for (i = 0; preferred_hostkeys[i] != NULL; ++i) {
        bool found = false;

        for (it = ssh_list_get_iterator(algo_list);
             it != NULL;
             it = it->next) {
            const char *algo = ssh_iterator_value(const char *, it);
            int cmp;
            int ok;

            cmp = strcmp(preferred_hostkeys[i], algo);
            if (cmp == 0) {
                ok = ssh_verify_existing_algo(SSH_HOSTKEYS, algo);
                if (ok) {
                    if (needcomma) {
                        strncat(methods_buffer,
                                ",",
                                sizeof(methods_buffer) - strlen(methods_buffer) - 1);
                    }
                    strncat(methods_buffer,
                            algo,
                            sizeof(methods_buffer) - strlen(methods_buffer) - 1);
                    needcomma = 1;
                    found = true;
                }
            }
        }
        /* Collect the rest of the algorithms in other buffer, that will
         * follow the preferred buffer. This will signalize all the algorithms
         * we are willing to accept.
         */
        if (!found) {
            snprintf(tail_buffer + strlen(tail_buffer),
                     sizeof(tail_buffer) - strlen(tail_buffer),
                     ",%s", preferred_hostkeys[i]);
        }
    }
    ssh_list_free(algo_list);

    if (strlen(methods_buffer) == 0) {
        SSH_LOG(SSH_LOG_DEBUG,
                "No supported kex method for existing key in known_hosts file");
        return NULL;
    }

    /* Append the supported list to the preferred.
     * The length is maximum 128 + 128 + 1, which will not overflow
     */
    len = strlen(methods_buffer) + strlen(tail_buffer) + 1;
    new_hostkeys = malloc(len);
    if (new_hostkeys == NULL) {
        ssh_set_error_oom(session);
        return NULL;
    }
    snprintf(new_hostkeys, len,
             "%s%s", methods_buffer, tail_buffer);

    SSH_LOG(SSH_LOG_DEBUG,
            "Changing host key method to \"%s\"",
            new_hostkeys);

    return new_hostkeys;
}

/**
 * @brief sets the key exchange parameters to be sent to the server,
 *        in function of the options and available methods.
 */
int ssh_set_client_kex(ssh_session session)
{
    struct ssh_kex_struct *client= &session->next_crypto->client_kex;
    const char *wanted;
    char *kex = NULL;
    char *kex_tmp = NULL;
    int ok;
    int i;
    size_t kex_len, len;

    ok = ssh_get_random(client->cookie, 16, 0);
    if (!ok) {
        ssh_set_error(session, SSH_FATAL, "PRNG error");
        return SSH_ERROR;
    }

    memset(client->methods, 0, KEX_METHODS_SIZE * sizeof(char **));
    /* first check if we have specific host key methods */
    if(session->opts.wanted_methods[SSH_HOSTKEYS] == NULL){
    	/* Only if no override */
    	session->opts.wanted_methods[SSH_HOSTKEYS] =
    			ssh_client_select_hostkeys(session);
    }

    for (i = 0; i < KEX_METHODS_SIZE; i++) {
        wanted = session->opts.wanted_methods[i];
        if (wanted == NULL)
            wanted = default_methods[i];
        client->methods[i] = strdup(wanted);
        if (client->methods[i] == NULL) {
            ssh_set_error_oom(session);
            return SSH_ERROR;
        }
    }

    /* For rekeying, skip the extension negotiation */
    if (session->session_state == SSH_SESSION_STATE_AUTHENTICATED) {
        return SSH_OK;
    }

    /* Here we append  ext-info-c  to the list of kex algorithms */
    kex = client->methods[SSH_KEX];
    len = strlen(kex);
    if (len + strlen(KEX_EXTENSION_CLIENT) + 2 < len) {
        /* Overflow */
        return SSH_ERROR;
    }
    kex_len = len + strlen(KEX_EXTENSION_CLIENT) + 2; /* comma, NULL */
    kex_tmp = realloc(kex, kex_len);
    if (kex_tmp == NULL) {
        free(kex);
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    snprintf(kex_tmp + len, kex_len - len, ",%s", KEX_EXTENSION_CLIENT);
    client->methods[SSH_KEX] = kex_tmp;

    return SSH_OK;
}

/** @brief Select the different methods on basis of client's and
 * server's kex messages, and watches out if a match is possible.
 */
int ssh_kex_select_methods (ssh_session session){
    struct ssh_kex_struct *server = &session->next_crypto->server_kex;
    struct ssh_kex_struct *client = &session->next_crypto->client_kex;
    char *ext_start = NULL;
    int i;

    /* Here we should drop the  ext-info-c  from the list so we avoid matching.
     * it. We added it to the end, so we can just truncate the string here */
    ext_start = strstr(client->methods[SSH_KEX], ","KEX_EXTENSION_CLIENT);
    if (ext_start != NULL) {
        ext_start[0] = '\0';
    }

    for (i = 0; i < KEX_METHODS_SIZE; i++) {
        session->next_crypto->kex_methods[i]=ssh_find_matching(server->methods[i],client->methods[i]);
        if(session->next_crypto->kex_methods[i] == NULL && i < SSH_LANG_C_S){
            ssh_set_error(session,SSH_FATAL,"kex error : no match for method %s: server [%s], client [%s]",
                    ssh_kex_descriptions[i],server->methods[i],client->methods[i]);
            return SSH_ERROR;
        } else if ((i >= SSH_LANG_C_S) && (session->next_crypto->kex_methods[i] == NULL)) {
            /* we can safely do that for languages */
            session->next_crypto->kex_methods[i] = strdup("");
        }
    }
    if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group1-sha1") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP1_SHA1;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group14-sha1") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP14_SHA1;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group16-sha512") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP16_SHA512;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group18-sha512") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP18_SHA512;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "ecdh-sha2-nistp256") == 0){
      session->next_crypto->kex_type=SSH_KEX_ECDH_SHA2_NISTP256;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "ecdh-sha2-nistp384") == 0){
      session->next_crypto->kex_type=SSH_KEX_ECDH_SHA2_NISTP384;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "ecdh-sha2-nistp521") == 0){
      session->next_crypto->kex_type=SSH_KEX_ECDH_SHA2_NISTP521;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "curve25519-sha256@libssh.org") == 0){
      session->next_crypto->kex_type=SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "curve25519-sha256") == 0){
      session->next_crypto->kex_type=SSH_KEX_CURVE25519_SHA256;
    }
    SSH_LOG(SSH_LOG_INFO, "Negotiated %s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
            session->next_crypto->kex_methods[SSH_KEX],
            session->next_crypto->kex_methods[SSH_HOSTKEYS],
            session->next_crypto->kex_methods[SSH_CRYPT_C_S],
            session->next_crypto->kex_methods[SSH_CRYPT_S_C],
            session->next_crypto->kex_methods[SSH_MAC_C_S],
            session->next_crypto->kex_methods[SSH_MAC_S_C],
            session->next_crypto->kex_methods[SSH_COMP_C_S],
            session->next_crypto->kex_methods[SSH_COMP_S_C],
            session->next_crypto->kex_methods[SSH_LANG_C_S],
            session->next_crypto->kex_methods[SSH_LANG_S_C]
    );
    return SSH_OK;
}


/* this function only sends the predefined set of kex methods */
int ssh_send_kex(ssh_session session, int server_kex) {
  struct ssh_kex_struct *kex = (server_kex ? &session->next_crypto->server_kex :
      &session->next_crypto->client_kex);
  ssh_string str = NULL;
  int i;
  int rc;

  rc = ssh_buffer_pack(session->out_buffer,
                       "bP",
                       SSH2_MSG_KEXINIT,
                       16,
                       kex->cookie); /* cookie */
  if (rc != SSH_OK)
    goto error;
  if (ssh_hashbufout_add_cookie(session) < 0) {
    goto error;
  }

  ssh_list_kex(kex);

  for (i = 0; i < KEX_METHODS_SIZE; i++) {
    str = ssh_string_from_char(kex->methods[i]);
    if (str == NULL) {
      goto error;
    }

    if (ssh_buffer_add_ssh_string(session->out_hashbuf, str) < 0) {
      goto error;
    }
    if (ssh_buffer_add_ssh_string(session->out_buffer, str) < 0) {
      goto error;
    }
    ssh_string_free(str);
    str = NULL;
  }

  rc = ssh_buffer_pack(session->out_buffer,
                       "bd",
                       0,
                       0);
  if (rc != SSH_OK) {
    goto error;
  }

  if (ssh_packet_send(session) == SSH_ERROR) {
    return -1;
  }

  return 0;
error:
  ssh_buffer_reinit(session->out_buffer);
  ssh_buffer_reinit(session->out_hashbuf);
  ssh_string_free(str);

  return -1;
}

/* returns 1 if at least one of the name algos is in the default algorithms table */
int ssh_verify_existing_algo(enum ssh_kex_types_e algo, const char *name)
{
    char *ptr;

    if (algo > SSH_LANG_S_C) {
        return -1;
    }

    ptr=ssh_find_matching(supported_methods[algo],name);
    if(ptr){
        free(ptr);
        return 1;
    }
    return 0;
}

/* returns a copy of the provided list if everything is supported,
 * otherwise a new list of the supported algorithms */
char *ssh_keep_known_algos(enum ssh_kex_types_e algo, const char *list)
{
    if (algo > SSH_LANG_S_C) {
        return NULL;
    }

    return ssh_find_all_matching(supported_methods[algo], list);
}
