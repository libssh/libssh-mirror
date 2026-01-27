/*
 * Copyright 2026 libssh authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define LIBSSH_STATIC 1
#include "libssh/libssh.h"
#include "libssh/sftp.h"
#include "libssh/sftp_priv.h"

static void fuzz_sftp_parse_attr(uint8_t version, int expectname,
                                  const uint8_t *data, size_t size)
{
    ssh_session session = NULL;
    sftp_session sftp = NULL;
    ssh_buffer buffer = NULL;
    sftp_attributes attr = NULL;

    session = ssh_new();
    if (session == NULL) {
        return;
    }

    sftp = calloc(1, sizeof(struct sftp_session_struct));
    if (sftp == NULL) {
        ssh_free(session);
        return;
    }
    sftp->session = session;
    sftp->version = version;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        free(sftp);
        ssh_free(session);
        return;
    }

    /* Main fuzzing target sftp_parse_attr */
    /* It parses untrusted sftp message from client */
    if (ssh_buffer_add_data(buffer, data, size) == SSH_OK) {
        attr = sftp_parse_attr(sftp, buffer, expectname);
        if (attr != NULL) {
            sftp_attributes_free(attr);
        }
    }

    ssh_buffer_free(buffer);
    free(sftp);
    ssh_free(session);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Minimum bytes for a valid sftp message */
    if (size < 4) {
        return 0;
    }

    /* Test all combinations */
    fuzz_sftp_parse_attr(3, 0, data, size);  /* SFTP v3, no name */
    fuzz_sftp_parse_attr(3, 1, data, size);  /* SFTP v3, with name */
    fuzz_sftp_parse_attr(4, 0, data, size);  /* SFTP v4, no name */
    fuzz_sftp_parse_attr(4, 1, data, size);  /* SFTP v4, with name *

    return 0;
}
