/*
 * pki_container_openssh.c
 * This file is part of the SSH Library
 *
 * Copyright (c) 2013,2014 Aris Adamantiadis <aris@badcode.be>
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
 * @ingroup libssh_pki
 * *
 * @{
 */

#include "config.h"

#include <ctype.h>
#include <string.h>

#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/buffer.h"


/**
 * @internal
 *
 * @brief Import a private key from a ssh buffer.
 *
 * @param[in] key_blob_buffer The key blob to import as specified in
 *                            key.c:key_private_serialize in OpenSSH source
 *                            code.
 *
 * @param[out] pkey     A pointer where the allocated key can be stored. You
 *                      need to free the memory.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_key_free()
 */
static int pki_openssh_import_privkey_blob(ssh_buffer key_blob_buffer,
                                           ssh_key *pkey)
{
    enum ssh_keytypes_e type;
    char *type_s = NULL;
    ssh_key key = NULL;
    ssh_string pubkey = NULL, privkey = NULL;
    int rc;

    if (pkey == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_buffer_unpack(key_blob_buffer, "s", &type_s);
    if (rc == SSH_ERROR){
        ssh_pki_log("Unpack error");
        return SSH_ERROR;
    }

    type = ssh_key_type_from_name(type_s);
    if (type == SSH_KEYTYPE_UNKNOWN) {
        ssh_pki_log("Unknown key type found!");
        return SSH_ERROR;
    }
    SAFE_FREE(type_s);

    key = ssh_key_new();
    if (key == NULL) {
        ssh_pki_log("Out of memory");
        return SSH_ERROR;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC;

    switch (type) {
    case SSH_KEYTYPE_ED25519:
        rc = ssh_buffer_unpack(key_blob_buffer, "SS", &pubkey, &privkey);
        if (rc != SSH_OK){
            ssh_pki_log("Unpack error");
            goto fail;
        }
        if(ssh_string_len(pubkey) != ED25519_PK_LEN ||
                ssh_string_len(privkey) != ED25519_SK_LEN){
            ssh_pki_log("Invalid ed25519 key len");
            goto fail;
        }
        key->ed25519_privkey = malloc(ED25519_SK_LEN);
        key->ed25519_pubkey = malloc(ED25519_PK_LEN);
        if(key->ed25519_privkey == NULL || key->ed25519_pubkey == NULL){
            goto fail;
        }
        memcpy(key->ed25519_privkey, ssh_string_data(privkey), ED25519_SK_LEN);
        memcpy(key->ed25519_pubkey, ssh_string_data(pubkey), ED25519_PK_LEN);
        memset(ssh_string_data(privkey), 0, ED25519_SK_LEN);
        SAFE_FREE(privkey);
        SAFE_FREE(pubkey);
        break;
    case SSH_KEYTYPE_DSS:
        /* p,q,g,pub_key,priv_key */
    case SSH_KEYTYPE_RSA:
        /* n,e,d,iqmp,p,q */
    case SSH_KEYTYPE_RSA1:
    case SSH_KEYTYPE_ECDSA:
        /* curve_name, group, privkey */
        ssh_pki_log("Unsupported private key method %s", key->type_c);
        goto fail;
    case SSH_KEYTYPE_UNKNOWN:
        ssh_pki_log("Unknown private key protocol %s", key->type_c);
        goto fail;
    }

    *pkey = key;
    return SSH_OK;
fail:
    ssh_key_free(key);
    if(privkey != NULL){
        memset(ssh_string_data(privkey), 0, ssh_string_len(privkey));
    }
    SAFE_FREE(pubkey);
    SAFE_FREE(privkey);

    return SSH_ERROR;
}

/** @internal
 * @brief Import a private key in OpenSSH (new) format. This format is
 * typically used with ed25519 keys but can be used for others.
 */
 ssh_key ssh_pki_openssh_privkey_import(const char *text_key,
                                        const char *passphrase,
                                        ssh_auth_callback auth_fn,
                                        void *auth_data)
{
    const char *ptr=text_key;
    const char *end;
    char *base64;
    int cmp;
    int rc;
    int i;
    ssh_buffer buffer = NULL, privkey_buffer=NULL;
    char *magic = NULL, *ciphername = NULL, *kdfname = NULL;
    uint32_t nkeys = 0, checkint1, checkint2;
    ssh_string kdfoptions = NULL;
    ssh_string pubkey0 = NULL;
    ssh_string privkeys = NULL;
    ssh_key key = NULL;

    cmp = strncmp(ptr, OPENSSH_HEADER_BEGIN, strlen(OPENSSH_HEADER_BEGIN));
    if (cmp != 0){
        SSH_LOG(SSH_LOG_WARN, "Not an OpenSSH private key (no header)");
        goto error;
    }
    ptr += strlen(OPENSSH_HEADER_BEGIN);
    while(ptr[0] != '\0' && !isspace((int)ptr[0])) {
        ptr++;
    }
    end = strstr(ptr, OPENSSH_HEADER_END);
    if (end == NULL){
        SSH_LOG(SSH_LOG_WARN, "Not an OpenSSH private key (no footer)");
        goto error;
    }
    base64 = malloc(end - ptr + 1);
    if (base64 == NULL){
        goto error;
    }
    for (i = 0; ptr < end; ptr++){
        if (!isspace((int)ptr[0])) {
            base64[i] = ptr[0];
            i++;
        }
    }
    base64[i] = '\0';
    buffer = base64_to_bin(base64);
    SAFE_FREE(base64);
    if (buffer == NULL){
        SSH_LOG(SSH_LOG_WARN, "Not an OpenSSH private key (base64 error)");
        goto error;
    }
    rc = ssh_buffer_unpack(buffer, "PssSdSS",
                           strlen(OPENSSH_AUTH_MAGIC) + 1,
                           &magic,
                           &ciphername,
                           &kdfname,
                           &kdfoptions,
                           &nkeys,
                           &pubkey0,
                           &privkeys);
    if (rc == SSH_ERROR){
        SSH_LOG(SSH_LOG_WARN, "Not an OpenSSH private key (unpack error)");
        goto error;
    }
    cmp = strncmp(magic, OPENSSH_AUTH_MAGIC, strlen(OPENSSH_AUTH_MAGIC));
    if (cmp != 0){
        SSH_LOG(SSH_LOG_WARN, "Not an OpenSSH private key (bad magic)");
        goto error;
    }
    SSH_LOG(SSH_LOG_INFO, "Opening OpenSSH private key: ciphername: %s, kdf: %s, nkeys: %d\n", ciphername, kdfname, nkeys);
    if (strcmp(ciphername, "none") != 0){
        SSH_LOG(SSH_LOG_WARN, "Unsupported cipher %s", ciphername);
        goto error;
    }
    if (nkeys != 1){
        SSH_LOG(SSH_LOG_WARN, "Opening OpenSSH private key: only 1 key supported (%d available)", nkeys);
        goto error;
    }

    privkey_buffer = ssh_buffer_new();
    ssh_buffer_add_data(privkey_buffer, ssh_string_data(privkeys), ssh_string_len(privkeys));
    rc = ssh_buffer_unpack(privkey_buffer, "dd", &checkint1, &checkint2);
    if (rc == SSH_ERROR || checkint1 != checkint2){
        SSH_LOG(SSH_LOG_WARN, "OpenSSH private key unpack error (correct password?)");
        goto error;
    }
    rc = pki_openssh_import_privkey_blob(privkey_buffer, &key);

error:
    if(buffer != NULL){
        ssh_buffer_free(buffer);
        buffer = NULL;
    }
    if(privkey_buffer != NULL){
        ssh_buffer_free(privkey_buffer);
        privkey_buffer = NULL;
    }
    SAFE_FREE(magic);
    SAFE_FREE(ciphername);
    SAFE_FREE(kdfname);
    SAFE_FREE(kdfoptions);
    SAFE_FREE(pubkey0);
    SAFE_FREE(privkeys);
    return key;
}

/**
 * @}
 */
