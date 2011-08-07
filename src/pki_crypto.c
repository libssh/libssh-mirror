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

#endif /* _PKI_CRYPTO_H */
