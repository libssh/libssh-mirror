/*
 * config_parser.c - Common configuration file parser functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009-2013    by Andreas Schneider <asn@cryptomilk.org>
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

#include "libssh/config_parser.h"
#include "libssh/priv.h"
#include "libssh/misc.h"

/* Returns the original string after skipping the leading whitespace
 * until finding LF.
 * This is useful in case we need to get the rest of the line (for example
 * external command).
 */
char *ssh_config_get_cmd(char **str)
{
    register char *c = NULL;
    char *r = NULL;

    /* Ignore leading spaces */
    for (c = *str; *c; c++) {
        if (!isspace((unsigned char)*c)) {
            break;
        }
    }

    for (r = c; *c; c++) {
        if (*c == '\n') {
            *c = '\0';
            goto out;
        }
    }

out:
    *str = c + 1;

    return r;
}

/* Returns the next token delimited by whitespace or equal sign (=)
 * respecting the quotes creating separate token (including whitespaces).
 */
char *ssh_config_get_token_info(char **str, struct ssh_config_token_info *info)
{
    register char *c = NULL;
    /* Write cursor for the normalized token. Quotes and selected escape
     * characters are dropped while still returning a pointer into the original
     * buffer.
     */
    char *dst = NULL;
    bool had_equal = false;
    bool found = false;
    bool invalid = false;
    char *r = NULL;
    char inquote = '\0';

    if (info != NULL) {
        info->found = false;
        info->had_equal = false;
        info->invalid = false;
    }

    /* Ignore leading spaces */
    for (c = *str; *c; c++) {
        if (!isspace((unsigned char)*c)) {
            break;
        }
    }

    /* End of string or a bare newline means there is no token here, not an
     * explicit empty token (""). Keep found=false in both cases; the newline
     * branch also consumes the line boundary.
     */
    if (*c == '\0') {
        r = c;
        goto out;
    }
    if (*c == '\n') {
        r = c;
        *c = '\0';
        c++;
        goto out;
    }

    found = true;

    /* Terminate on space, equal or newline.
     * Embedded quotes are stripped and used to protect spaces from being
     * seen as delimiters.
     */
    r = dst = c;
    for (; *c; c++) {
        /* Process backslash escapes matching OpenSSH's argv_split():
         * \\, \', \", and \<blank> are recognized. The backslash is
         * dropped and the escaped character is kept. Unrecognized
         * escapes preserve the backslash literally.
         */
        if (*c == '\\' &&
            (c[1] == '\\' || c[1] == '\'' || c[1] == '\"' ||
             isspace((unsigned char)c[1]))) {
            c++;
            *dst++ = *c;
        } else if (*c == '\n' || (!inquote && (isspace((unsigned char)*c) || *c == '='))) {
            had_equal = (*c == '=');
            *dst = '\0';
            c++;
            break;
        } else if (inquote) {
            if (*c == inquote) {
                inquote = '\0';
            } else {
                *dst++ = *c;
            }
        } else if (*c == '\'' || *c == '\"') {
            inquote = *c;
        } else {
            *dst++ = *c;
        }
    }
    if (inquote) {
        invalid = true;
    }
    if (*c == '\0') {
        *dst = '\0';
    }

    /* Skip any other remaining whitespace */
    while (isspace((unsigned char)*c) || *c == '\n' ||
           (!had_equal && *c == '=')) {
        if (*c == '=') {
            had_equal = true;
        }
        c++;
    }
out:
    *str = c;
    if (info != NULL) {
        info->found = found;
        info->had_equal = had_equal;
        info->invalid = invalid;
    }
    return r;
}

char *ssh_config_get_token(char **str)
{
    return ssh_config_get_token_info(str, NULL);
}

long ssh_config_get_long(char **str, long notfound)
{
    char *p = NULL, *endp = NULL;
    long i;

    p = ssh_config_get_token(str);
    if (p && *p) {
        i = strtol(p, &endp, 10);
        if (p == endp || *endp != '\0') {
            return notfound;
        }
        return i;
    }

    return notfound;
}

const char *ssh_config_get_str_tok(char **str, const char *def)
{
    char *p = NULL;

    p = ssh_config_get_token(str);
    if (p && *p) {
        return p;
    }

    return def;
}

int ssh_config_get_yesno(char **str, int notfound)
{
    const char *p = NULL;

    p = ssh_config_get_str_tok(str, NULL);
    if (p == NULL) {
        return notfound;
    }

    {
        int is_yes = (strcasecmp(p, "yes") == 0);
        int is_true = (strcasecmp(p, "true") == 0);
        if (is_yes || is_true) {
            return 1;
        } else {
            int is_no = (strcasecmp(p, "no") == 0);
            int is_false = (strcasecmp(p, "false") == 0);
            if (is_no || is_false) {
                return 0;
            }
        }

    }

    return notfound;
}

int ssh_config_parse_uri(const char *tok,
                         char **username,
                         char **hostname,
                         char **port,
                         bool ignore_port,
                         bool strict)
{
    const char *endp = NULL;
    long port_n;
    int rc;

    /* Sanitize inputs */
    if (username != NULL) {
        *username = NULL;
    }
    if (hostname != NULL) {
        *hostname = NULL;
    }
    if (port != NULL) {
        *port = NULL;
    }

    /* Username part (optional) */
    endp = strrchr(tok, '@');
    if (endp != NULL) {
        /* Zero-length username is not valid */
        if (tok == endp) {
            goto error;
        }
        if (username != NULL) {
            *username = strndup(tok, endp - tok);
            if (*username == NULL) {
                goto error;
            }
            rc = ssh_check_username_syntax(*username);
            if (rc != SSH_OK) {
                goto error;
            }
        }
        tok = endp + 1;
        /* If there is second @ character, this does not look like our URI */
        endp = strchr(tok, '@');
        if (endp != NULL) {
            goto error;
        }
    }

    /* Hostname */
    if (*tok == '[') {
        /* IPv6 address is enclosed with square brackets */
        tok++;
        endp = strchr(tok, ']');
        if (endp == NULL) {
            goto error;
        }
    } else if (!ignore_port) {
        /* Hostnames or aliases expand to the last colon (if port is requested)
         * or to the end */
        endp = strrchr(tok, ':');
        if (endp == NULL) {
            endp = strchr(tok, '\0');
        }
    } else {
        /* If no port is requested, expand to the end of line
         * (to accommodate the IPv6 addresses) */
        endp = strchr(tok, '\0');
    }
    if (tok == endp) {
        /* Zero-length hostnames are not valid */
        goto error;
    }
    if (hostname != NULL) {
        *hostname = strndup(tok, endp - tok);
        if (*hostname == NULL) {
            goto error;
        }
        if (strict) {
            /* if not an ip, check syntax */
            rc = ssh_is_ipaddr(*hostname);
            if (rc == 0) {
                rc = ssh_check_hostname_syntax(*hostname);
                if (rc != SSH_OK) {
                    goto error;
                }
            }
        } else {
            /* Reject shell metacharacters to allow config aliases with
             * non-RFC1035 chars (e.g. %, _). Modeled on OpenSSH's
             * valid_hostname() in ssh.c. */
            const char *c = NULL;
            if ((*hostname)[0] == '-') {
                goto error;
            }
            for (c = *hostname; *c != '\0'; c++) {
                const char *is_meta = strchr(SSH_DANGEROUS_SHELL_CHARS, *c);
                int is_space = isspace((unsigned char)*c);
                int is_ctrl = iscntrl((unsigned char)*c);
                if (is_meta != NULL || is_space || is_ctrl) {
                    goto error;
                }
            }
        }
    }
    /* Skip also the closing bracket */
    if (*endp == ']') {
        endp++;
    }

    /* Port (optional) */
    if (*endp != '\0') {
        char *port_end = NULL;

        /* Verify the port is valid positive number */
        port_n = strtol(endp + 1, &port_end, 10);
        if (port_n < 1 || *port_end != '\0') {
            SSH_LOG(SSH_LOG_TRACE, "Failed to parse port number."
                    " The value '%ld' is invalid or there are some"
                    " trailing characters: '%s'", port_n, port_end);
            goto error;
        }
        if (port != NULL) {
            *port = strdup(endp + 1);
            if (*port == NULL) {
                goto error;
            }
        }
    }

    return SSH_OK;

error:
    if (username != NULL) {
        SAFE_FREE(*username);
    }
    if (hostname != NULL) {
        SAFE_FREE(*hostname);
    }
    if (port != NULL) {
        SAFE_FREE(*port);
    }
    return SSH_ERROR;
}

/**
 * @brief Get a path from a string, handling quotes and spaces.
 *
 * It handles single and double quotes and strips them from the result.
 * It also handles escaped characters (\\).
 * It preserves comment boundaries (#) unless inside quotes.
 *
 * @param[in,out] str Pointer to the string to parse. Updated to point
 *                    to the next token.
 *
 * @return  A pointer to the extracted path string, or NULL on error
 *          (e.g. unclosed quotes) or if no path is found.
 */
char *ssh_config_get_path(char **str)
{
    char *c = *str;
    char *r = NULL;
    char *out = NULL;
    char delimiter;
    bool in_double_quote = false;
    bool in_single_quote = false;

    /* Skip leading spaces */
    while (isblank((unsigned char)*c)) {
        c++;
    }

    if (*c == '\0' || *c == '\n' || *c == '#') {
        *str = c;
        return NULL;
    }

    r = out = c;

    for (; *c != '\0' && *c != '\n'; c++) {
        bool in_quotes = in_single_quote || in_double_quote;

        if (*c == '\\') {
            /* If we encounter an escape character, check if it's escaping something meaningful */
            if (c[1] == '\'' || c[1] == '\"' || c[1] == '\\' ||
                (!in_quotes && isblank((unsigned char)c[1]))) {
                c++; /* Skip the escape character */
            }
        } else if ((in_single_quote && *c == '\'') || (in_double_quote && *c == '\"')) {
            /* Closing quote */
            in_single_quote = false;
            in_double_quote = false;
            continue;
        } else if (!in_quotes) {
            /* We are outside of quotes - handle opening quotes and token boundaries */
            if (isblank((unsigned char)*c)) {
                break; /* Space means we've reached the end of the token */
            } else if (*c == '\'' || *c == '\"') {
                if (*c == '\'') {
                    in_single_quote = true;
                } else {
                    in_double_quote = true;
                }
                continue; /* Skip the opening quote character itself */
            }
        }

        /* Everything else (regular characters, and literal characters inside quotes) 
         * gets appended to the token */
        *out++ = *c;
    }

    /* Return NULL on unclosed quotes */
    if (in_double_quote || in_single_quote) {
        return NULL;
    }

    delimiter = *c;
    *out = '\0';

    /* Move past the delimiter for the next time this is called */
    if (delimiter != '\0' && delimiter != '\n' && delimiter != '#') {
        c++;
    }

    /* Skip any trailing whitespace as well */
    while (isblank((unsigned char)*c)) {
        c++;
    }

    *str = c;
    return r;
}
