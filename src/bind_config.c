/*
 * bind_config.c - Parse the SSH server configuration file
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2019 by Red Hat, Inc.
 *
 * Author: Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_GLOB_H
# include <glob.h>
#endif

#include "libssh/bind.h"
#include "libssh/bind_config.h"
#include "libssh/config_parser.h"
#include "libssh/priv.h"
#include "libssh/server.h"
#include "libssh/options.h"

#define MAX_LINE_SIZE 1024

struct ssh_bind_config_keyword_table_s {
  const char *name;
  enum ssh_bind_config_opcode_e opcode;
};

static struct ssh_bind_config_keyword_table_s
ssh_bind_config_keyword_table[] = {
    {
        .name   = "include",
        .opcode = BIND_CFG_INCLUDE
    },
    {
        .name   = "hostkey",
        .opcode = BIND_CFG_HOSTKEY
    },
    {
        .name   = "listenaddress",
        .opcode = BIND_CFG_LISTENADDRESS
    },
    {
        .name   = "port",
        .opcode = BIND_CFG_PORT
    },
    {
        .name   = "loglevel",
        .opcode = BIND_CFG_LOGLEVEL
    },
    {
        .name   = "ciphers",
        .opcode = BIND_CFG_CIPHERS
    },
    {
        .name   = "macs",
        .opcode = BIND_CFG_MACS
    },
    {
        .name   = "kexalgorithms",
        .opcode = BIND_CFG_KEXALGORITHMS
    },
    {
        .opcode = BIND_CFG_UNKNOWN,
    }
};

static enum ssh_bind_config_opcode_e
ssh_bind_config_get_opcode(char *keyword)
{
    int i;

    for (i = 0; ssh_bind_config_keyword_table[i].name != NULL; i++) {
        if (strcasecmp(keyword, ssh_bind_config_keyword_table[i].name) == 0) {
            return ssh_bind_config_keyword_table[i].opcode;
        }
    }

    return BIND_CFG_UNKNOWN;
}

static int
ssh_bind_config_parse_line(ssh_bind bind,
                           const char *line,
                           unsigned int count,
                           uint32_t *parser_flags,
                           uint8_t *seen);

static void local_parse_file(ssh_bind bind,
                             const char *filename,
                             uint32_t *parser_flags,
                             uint8_t *seen)
{
    FILE *f;
    char line[MAX_LINE_SIZE] = {0};
    unsigned int count = 0;
    int rv;

    f = fopen(filename, "r");
    if (f == NULL) {
        SSH_LOG(SSH_LOG_RARE, "Cannot find file %s to load",
                filename);
        return;
    }

    SSH_LOG(SSH_LOG_PACKET, "Reading additional configuration data from %s",
            filename);

    while (fgets(line, sizeof(line), f)) {
        count++;
        rv = ssh_bind_config_parse_line(bind, line, count, parser_flags, seen);
        if (rv < 0) {
            fclose(f);
            return;
        }
    }

    fclose(f);
    return;
}

#if defined(HAVE_GLOB) && defined(HAVE_GLOB_GL_FLAGS_MEMBER)
static void local_parse_glob(ssh_bind bind,
                             const char *fileglob,
                             uint32_t *parser_flags,
                             uint8_t *seen)
{
    glob_t globbuf = {
        .gl_flags = 0,
    };
    int rt;
    u_int i;

    rt = glob(fileglob, GLOB_TILDE, NULL, &globbuf);
    if (rt == GLOB_NOMATCH) {
        globfree(&globbuf);
        return;
    } else if (rt != 0) {
        SSH_LOG(SSH_LOG_RARE, "Glob error: %s",
                fileglob);
        globfree(&globbuf);
        return;
    }

    for (i = 0; i < globbuf.gl_pathc; i++) {
        local_parse_file(bind, globbuf.gl_pathv[i], parser_flags, seen);
    }

    globfree(&globbuf);
}
#endif /* HAVE_GLOB HAVE_GLOB_GL_FLAGS_MEMBER */


static int
ssh_bind_config_parse_line(ssh_bind bind,
                           const char *line,
                           unsigned int count,
                           uint32_t *parser_flags,
                           uint8_t *seen)
{
    enum ssh_bind_config_opcode_e opcode;
    const char *p = NULL;
    char *s = NULL, *x = NULL;
    char *keyword = NULL;
    size_t len;

    if (bind == NULL) {
        return -1;
    }

    if ((line == NULL) || (parser_flags == NULL)) {
        ssh_set_error_invalid(bind);
        return -1;
    }

    x = s = strdup(line);
    if (s == NULL) {
        ssh_set_error_oom(bind);
        return -1;
    }

    /* Remove trailing spaces */
    for (len = strlen(s) - 1; len > 0; len--) {
        if (! isspace(s[len])) {
            break;
        }
        s[len] = '\0';
    }

    keyword = ssh_config_get_token(&s);
    if (keyword == NULL || *keyword == '#' ||
            *keyword == '\0' || *keyword == '\n') {
        SAFE_FREE(x);
        return 0;
    }

    opcode = ssh_bind_config_get_opcode(keyword);
    if (*parser_flags == 1 &&
            opcode != BIND_CFG_HOSTKEY &&
            opcode != BIND_CFG_INCLUDE &&
            opcode > BIND_CFG_UNSUPPORTED) { /* Ignore all unknown types here */
        /* Skip all the options that were already applied */
        if (seen[opcode] != 0) {
            SAFE_FREE(x);
            return 0;
        }
        seen[opcode] = 1;
    }

    switch (opcode) {
    case BIND_CFG_INCLUDE:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parser_flags) {
#if defined(HAVE_GLOB) && defined(HAVE_GLOB_GL_FLAGS_MEMBER)
            local_parse_glob(bind, p, parser_flags, seen);
#else
            local_parse_file(bind, p, parser_flags, seen);
#endif /* HAVE_GLOB */
        }
        break;

    case BIND_CFG_HOSTKEY:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parser_flags) {
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, p);
        }
        break;
    case BIND_CFG_LISTENADDRESS:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parser_flags) {
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDADDR, p);
        }
        break;
    case BIND_CFG_PORT:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parser_flags) {
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT_STR, p);
        }
        break;
    case BIND_CFG_CIPHERS:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parser_flags) {
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_CIPHERS_C_S, p);
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_CIPHERS_S_C, p);
        }
        break;
    case BIND_CFG_MACS:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parser_flags) {
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HMAC_C_S, p);
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HMAC_S_C, p);
        }
        break;
    case BIND_CFG_LOGLEVEL:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parser_flags) {
            int value = -1;

            if (strcasecmp(p, "quiet") == 0) {
                value = SSH_LOG_NONE;
            } else if (strcasecmp(p, "fatal") == 0 ||
                    strcasecmp(p, "error")== 0 ||
                    strcasecmp(p, "info") == 0) {
                value = SSH_LOG_WARN;
            } else if (strcasecmp(p, "verbose") == 0) {
                value = SSH_LOG_INFO;
            } else if (strcasecmp(p, "DEBUG") == 0 ||
                    strcasecmp(p, "DEBUG1") == 0) {
                value = SSH_LOG_DEBUG;
            } else if (strcasecmp(p, "DEBUG2") == 0 ||
                    strcasecmp(p, "DEBUG3") == 0) {
                value = SSH_LOG_TRACE;
            }
            if (value != -1) {
                ssh_bind_options_set(bind, SSH_BIND_OPTIONS_LOG_VERBOSITY,
                        &value);
            }
        }
        break;
    case BIND_CFG_KEXALGORITHMS:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parser_flags) {
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_KEY_EXCHANGE, p);
        }
        break;
    case BIND_CFG_UNKNOWN:
        SSH_LOG(SSH_LOG_WARN, "Unknown option: %s, line: %d",
                keyword, count);
        break;
    case BIND_CFG_UNSUPPORTED:
        SSH_LOG(SSH_LOG_WARN, "Unsupported option: %s, line: %d",
                keyword, count);
        break;
    case BIND_CFG_NA:
        SSH_LOG(SSH_LOG_WARN, "Option not applicable: %s, line: %d",
                keyword, count);
        break;
    default:
        ssh_set_error(bind, SSH_FATAL, "ERROR - unimplemented opcode: %d",
                opcode);
        SAFE_FREE(x);
        return -1;
        break;
    }

    SAFE_FREE(x);
    return 0;
}

int ssh_bind_config_parse_file(ssh_bind bind, const char *filename)
{
    char line[MAX_LINE_SIZE] = {0};
    unsigned int count = 0;
    FILE *f;
    uint32_t parser_flags;
    int rv;

    /* This local table is used during the parsing of the current file (and
     * files included recursively in this file) to prevent an option to be
     * redefined, i.e. the first value set is kept. But this DO NOT prevent the
     * option to be redefined later by another file. */
    uint8_t seen[BIND_CFG_MAX] = {0};

    f = fopen(filename, "r");
    if (f == NULL) {
        return 0;
    }

    SSH_LOG(SSH_LOG_PACKET, "Reading configuration data from %s", filename);

    parser_flags = 1;
    while (fgets(line, sizeof(line), f)) {
        count++;
        rv = ssh_bind_config_parse_line(bind, line, count, &parser_flags, seen);
        if (rv) {
            fclose(f);
            return -1;
        }
    }

    fclose(f);
    return 0;
}
