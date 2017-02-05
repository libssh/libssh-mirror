/*
 * known_hosts: Host and public key verification.
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 * Copyright (c) 2009-2017 by Andreas Schneider <asn@cryptomilk.org>
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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/options.h"
#include "libssh/misc.h"
#include "libssh/pki.h"

static int hash_hostname(const char *name,
                         unsigned char *salt,
                         unsigned int salt_size,
                         unsigned char **hash,
                         unsigned int *hash_size)
{
    HMACCTX mac_ctx;

    mac_ctx = hmac_init(salt, salt_size, SSH_HMAC_SHA1);
    if (mac_ctx == NULL) {
        return SSH_ERROR;
    }

    hmac_update(mac_ctx, name, strlen(name));
    hmac_final(mac_ctx, *hash, hash_size);

    return SSH_OK;
}

static int match_hashed_hostname(const char *host, const char *hashed_host)
{
    char *hashed;
    char *b64_hash;
    ssh_buffer salt = NULL;
    ssh_buffer hash = NULL;
    unsigned char hashed_buf[256] = {0};
    unsigned char *hashed_buf_ptr = hashed_buf;
    unsigned int hashed_buf_size = sizeof(hashed_buf);
    int cmp;
    int rc;
    int match = 0;

    cmp = strncmp(hashed_host, "|1|", 3);
    if (cmp != 0) {
        return 0;
    }

    hashed = strdup(hashed_host + 3);
    if (hashed == NULL) {
        return 0;
    }

    b64_hash = strchr(hashed, '|');
    if (b64_hash == NULL) {
        goto error;
    }
    *b64_hash = '\0';
    b64_hash++;

    salt = base64_to_bin(hashed);
    if (salt == NULL) {
        goto error;
    }

    hash = base64_to_bin(b64_hash);
    if (hash == NULL) {
        goto error;
    }

    rc = hash_hostname(host,
                       ssh_buffer_get(salt),
                       ssh_buffer_get_len(salt),
                       &hashed_buf_ptr,
                       &hashed_buf_size);
    if (rc != SSH_OK) {
        goto error;
    }

    if (hashed_buf_size != ssh_buffer_get_len(hash)) {
        goto error;
    }

    cmp = memcmp(hashed_buf, ssh_buffer_get(hash), hashed_buf_size);
    if (cmp == 0) {
        match = 1;
    }

error:
    free(hashed);
    ssh_buffer_free(salt);
    ssh_buffer_free(hash);

    return match;
}

/**
 * @brief Free an allocated ssh_knownhosts_entry.
 *
 * Use SSH_KNOWNHOSTS_ENTRY_FREE() to set the pointer to NULL.
 *
 * @param[in]  entry     The entry to free.
 */
void ssh_knownhosts_entry_free(struct ssh_knownhosts_entry *entry)
{
    if (entry == NULL) {
        return;
    }

    SAFE_FREE(entry->hostname);
    SAFE_FREE(entry->unparsed);
    ssh_key_free(entry->publickey);
    SAFE_FREE(entry->comment);
    SAFE_FREE(entry);
}

/**
 * @brief Parse a line from a known_hosts entry into a structure
 *
 * This parses an known_hosts entry into a structure with the key in a libssh
 * consumeable form. You can use the PKI key function to further work with it.
 *
 * @param[in]  hostname     The hostname to match the line to
 *
 * @param[in]  line         The line to compare and parse if we have a hostname
 *                          match.
 *
 * @param[in]  entry        A pointer to store the the allocated known_hosts
 *                          entry structure. The user needs to free the memory
 *                          using SSH_KNOWNHOSTS_ENTRY_FREE().
 *
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
int ssh_known_hosts_parse_line(const char *hostname,
                               const char *line,
                               struct ssh_knownhosts_entry **entry)
{
    struct ssh_knownhosts_entry *e = NULL;
    char *known_host = NULL;
    char *p;
    enum ssh_keytypes_e key_type;
    int match = 0;
    int rc = SSH_OK;

    known_host = strdup(line);
    if (known_host == NULL) {
        return SSH_ERROR;
    }

    /* match pattern for hostname or hashed hostname */
    p = strtok(known_host, " ");
    if (p == NULL ) {
        free(known_host);
        return SSH_ERROR;
    }

    e = calloc(1, sizeof(struct ssh_knownhosts_entry));
    if (e == NULL) {
        free(known_host);
        return SSH_ERROR;
    }

    if (hostname != NULL) {
        char *match_pattern = NULL;
        char *q;

        /* Hashed */
        if (p[0] == '|') {
            match = match_hashed_hostname(hostname, p);
        }

        for (q = strtok(p, ",");
             q != NULL;
             q = strtok(NULL, ",")) {
            int cmp;

            cmp = match_hostname(hostname, q, strlen(q));
            if (cmp == 1) {
                match = 1;
                break;
            }
        }
        SAFE_FREE(match_pattern);

        if (match == 0) {
            rc = SSH_AGAIN;
            goto out;
        }

        e->hostname = strdup(hostname);
        if (e->hostname == NULL) {
            rc = SSH_ERROR;
            goto out;
        }
    }

    /* Restart parsing */
    SAFE_FREE(known_host);
    known_host = strdup(line);
    if (known_host == NULL) {
        return SSH_ERROR;
    }

    p = strtok(known_host, " ");
    if (p == NULL ) {
        free(known_host);
        return SSH_ERROR;
    }

    e->unparsed = strdup(p);
    if (e->unparsed == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    /* pubkey type */
    p = strtok(NULL, " ");
    if (p == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    key_type = ssh_key_type_from_name(p);
    if (key_type == SSH_KEYTYPE_UNKNOWN) {
        SSH_LOG(SSH_LOG_WARN, "key type '%s' unknown!", p);
        rc = SSH_ERROR;
        goto out;
    }

    /* public key */
    p = strtok(NULL, " ");
    if (p == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_pki_import_pubkey_base64(p,
                                      key_type,
                                      &e->publickey);
    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_WARN,
                "Failed to parse %s key for entry: %s!",
                ssh_key_type_to_char(key_type),
                e->unparsed);
        goto out;
    }

    /* comment */
    p = strtok(NULL, " ");
    if (p != NULL) {
        p = strstr(line, p);
        e->comment = strdup(p);
        if (e->comment == NULL) {
            rc = SSH_ERROR;
            goto out;
        }
    }

    *entry = e;
    SAFE_FREE(known_host);

    return SSH_OK;
out:
    SAFE_FREE(known_host);
    ssh_knownhosts_entry_free(e);
    return rc;
}
