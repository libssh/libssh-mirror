/*
 * options.c - handle pre-connection options
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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

#include "config.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <pwd.h>
#else
#include <winsock2.h>
#endif
#include "libssh/config.h"
#include "libssh/config_parser.h"
#include "libssh/misc.h"
#include "libssh/options.h"
#include "libssh/pki.h"
#include "libssh/pki_context.h"
#include "libssh/pki_priv.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include <sys/types.h>
#include "libssh/misc.h"
#include "libssh/options.h"
#include "libssh/config_parser.h"
#include "libssh/gssapi.h"
#include "libssh/getopt.h"
#include "libssh/token.h"
#ifdef WITH_SERVER
#include "libssh/server.h"
#include "libssh/bind.h"
#include "libssh/bind_config.h"
#endif

/**
 * @addtogroup libssh_session
 * @{
 */

/**
 * @brief Duplicate the options of a session structure.
 *
 * If you make several sessions with the same options this is useful. You
 * cannot use twice the same option structure in ssh_connect.
 *
 * @param src           The session to use to copy the options.
 *
 * @param dest          A pointer to store the allocated session with duplicated
 *                      options. You have to free the memory using ssh_free()
 *
 * @returns             0 on success, -1 on error with errno set.
 *
 * @see ssh_connect()
 * @see ssh_free()
 */
int ssh_options_copy(ssh_session src, ssh_session *dest)
{
    ssh_session new = NULL;
    struct ssh_iterator *it = NULL;
    struct ssh_list *list = NULL;
    char *id = NULL;
    int i;

    if (src == NULL || dest == NULL) {
        return -1;
    }

    new = ssh_new();
    if (new == NULL) {
        return -1;
    }

    if (src->opts.username != NULL) {
        new->opts.username = strdup(src->opts.username);
        if (new->opts.username == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.host != NULL) {
        new->opts.host = strdup(src->opts.host);
        if (new->opts.host == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.originalhost != NULL) {
        new->opts.originalhost = strdup(src->opts.originalhost);
        if (new->opts.originalhost == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.tag != NULL) {
        new->opts.tag = strdup(src->opts.tag);
        if (new->opts.tag == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.config_hostname != NULL) {
        new->opts.config_hostname = strdup(src->opts.config_hostname);
        if (new->opts.config_hostname == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.bindaddr != NULL) {
        new->opts.bindaddr = strdup(src->opts.bindaddr);
        if (new->opts.bindaddr == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    /* Remove the default identities */
    for (id = ssh_list_pop_head(char *, new->opts.identity_non_exp);
         id != NULL;
         id = ssh_list_pop_head(char *, new->opts.identity_non_exp)) {
        SAFE_FREE(id);
    }
    /*
     * The new session was created by ssh_new() which always allocates
     * identity_non_exp and populates it with default identity paths.
     * So it is guaranteed to be non-NULL here and does not need the
     * lazy allocation pattern used for other option lists.
     */
    list = new->opts.identity_non_exp;
    it = ssh_list_get_iterator(src->opts.identity_non_exp);
    for (i = 0; i < 2; i++) {
        while (it) {
            int rc;

            id = strdup(ssh_iterator_value(char *, it));
            if (id == NULL) {
                ssh_free(new);
                return -1;
            }

            rc = ssh_list_append(list, id);
            if (rc < 0) {
                free(id);
                ssh_free(new);
                return -1;
            }
            id = NULL;
            it = it->next;
        }

        /* Allocate identity list only when the source has entries to copy */
        if (src->opts.identity == NULL) {
            break;
        }
        list = new->opts.identity;
        if (list == NULL) {
            list = ssh_list_new();
            if (list == NULL) {
                ssh_free(new);
                return -1;
            }
            new->opts.identity = list;
        }
        it = ssh_list_get_iterator(src->opts.identity);
    }

    if (src->opts.certificate_non_exp != NULL) {
        list = new->opts.certificate_non_exp;
        if (list == NULL) {
            list = ssh_list_new();
            if (list == NULL) {
                ssh_free(new);
                return -1;
            }
            new->opts.certificate_non_exp = list;
        }
        it = ssh_list_get_iterator(src->opts.certificate_non_exp);
        for (i = 0; i < 2; i++) {
            while (it) {
                int rc;

                id = strdup(ssh_iterator_value(char *, it));
                if (id == NULL) {
                    ssh_free(new);
                    return -1;
                }

                rc = ssh_list_append(list, id);
                if (rc < 0) {
                    free(id);
                    ssh_free(new);
                    return -1;
                }
                id = NULL;
                it = it->next;
            }

            /* copy the certificate list only if the source has one */
            if (src->opts.certificate == NULL) {
                break;
            }
            list = new->opts.certificate;
            if (list == NULL) {
                list = ssh_list_new();
                if (list == NULL) {
                    ssh_free(new);
                    return -1;
                }
                new->opts.certificate = list;
            }
            it = ssh_list_get_iterator(src->opts.certificate);
        }
    }

    it = ssh_list_get_iterator(src->opts.local_forward);
    while (it) {
        int rc = 0;
        char *pattern = strdup(ssh_iterator_value(char *, it));

        if (pattern == NULL) {
            ssh_free(new);
            return -1;
        }
        if (new->opts.local_forward == NULL) {
            new->opts.local_forward = ssh_list_new();
            if (new->opts.local_forward == NULL) {
                free(pattern);
                ssh_free(new);
                return -1;
            }
        }
        rc = ssh_list_append(new->opts.local_forward, pattern);
        if (rc < 0) {
            free(pattern);
            ssh_free(new);
            return -1;
        }
        it = it->next;
    }

    it = ssh_list_get_iterator(src->opts.remote_forward);
    while (it) {
        int rc = 0;
        char *pattern = strdup(ssh_iterator_value(char *, it));

        if (pattern == NULL) {
            ssh_free(new);
            return -1;
        }
        if (new->opts.remote_forward == NULL) {
            new->opts.remote_forward = ssh_list_new();
            if (new->opts.remote_forward == NULL) {
                free(pattern);
                ssh_free(new);
                return -1;
            }
        }
        rc = ssh_list_append(new->opts.remote_forward, pattern);
        if (rc < 0) {
            free(pattern);
            ssh_free(new);
            return -1;
        }
        it = it->next;
    }

    if (src->opts.sshdir != NULL) {
        new->opts.sshdir = strdup(src->opts.sshdir);
        if (new->opts.sshdir == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.knownhosts != NULL) {
        new->opts.knownhosts = strdup(src->opts.knownhosts);
        if (new->opts.knownhosts == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.global_knownhosts != NULL) {
        new->opts.global_knownhosts = strdup(src->opts.global_knownhosts);
        if (new->opts.global_knownhosts == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    for (i = 0; i < SSH_KEX_METHODS; i++) {
        if (src->opts.wanted_methods[i] != NULL) {
            new->opts.wanted_methods[i] = strdup(src->opts.wanted_methods[i]);
            if (new->opts.wanted_methods[i] == NULL) {
                ssh_free(new);
                return -1;
            }
        }
    }

    if (src->opts.ProxyCommand != NULL) {
        new->opts.ProxyCommand = strdup(src->opts.ProxyCommand);
        if (new->opts.ProxyCommand == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.pubkey_accepted_types != NULL) {
        new->opts.pubkey_accepted_types = strdup(src->opts.pubkey_accepted_types);
        if (new->opts.pubkey_accepted_types == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.gss_server_identity != NULL) {
        new->opts.gss_server_identity = strdup(src->opts.gss_server_identity);
        if (new->opts.gss_server_identity == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.gss_client_identity != NULL) {
        new->opts.gss_client_identity = strdup(src->opts.gss_client_identity);
        if (new->opts.gss_client_identity == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.control_path != NULL) {
        new->opts.control_path = strdup(src->opts.control_path);
        if (new->opts.control_path == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.forward_agent_sock_path != NULL) {
        new->opts.forward_agent_sock_path = strdup(src->opts.forward_agent_sock_path);
        if (new->opts.forward_agent_sock_path == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.preferred_authentications != NULL) {
        new->opts.preferred_authentications = strdup(src->opts.preferred_authentications);
        if (new->opts.preferred_authentications == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    it = ssh_list_get_iterator(src->opts.send_env);
    while (it) {
        int rc = 0;
        char *pattern = strdup(ssh_iterator_value(char *, it));

        if (pattern == NULL) {
            ssh_free(new);
            return -1;
        }
        if (new->opts.send_env == NULL) {
            new->opts.send_env = ssh_list_new();
            if (new->opts.send_env == NULL) {
                free(pattern);
                ssh_free(new);
                return -1;
            }
        }
        rc = ssh_list_append(new->opts.send_env, pattern);
        if (rc < 0) {
            free(pattern);
            ssh_free(new);
            return -1;
        }
        it = it->next;
    }

    memcpy(new->opts.options_seen, src->opts.options_seen,
           sizeof(new->opts.options_seen));

    new->opts.fd                    = src->opts.fd;
    new->opts.port                  = src->opts.port;
    new->opts.timeout               = src->opts.timeout;
    new->opts.timeout_usec          = src->opts.timeout_usec;
    new->opts.compressionlevel      = src->opts.compressionlevel;
    new->opts.StrictHostKeyChecking = src->opts.StrictHostKeyChecking;
    new->opts.gss_delegate_creds    = src->opts.gss_delegate_creds;
    new->opts.flags                 = src->opts.flags;
    new->opts.pubkey_auth = src->opts.pubkey_auth;
    new->opts.nodelay               = src->opts.nodelay;
    new->opts.config_processed      = src->opts.config_processed;
    new->opts.control_master        = src->opts.control_master;
    new->opts.number_of_password_prompts = src->opts.number_of_password_prompts;
    new->opts.request_tty           = src->opts.request_tty;
    new->opts.escape_char           = src->opts.escape_char;
    new->opts.address_family        = src->opts.address_family;
    new->opts.exit_on_forward_failure = src->opts.exit_on_forward_failure;
    new->opts.server_alive_interval = src->opts.server_alive_interval;
    new->opts.server_alive_count_max = src->opts.server_alive_count_max;
    new->opts.forward_agent         = src->opts.forward_agent;
    new->common.log_verbosity       = src->common.log_verbosity;
    new->common.callbacks           = src->common.callbacks;

    SSH_PKI_CTX_FREE(new->pki_context);
    if (src->pki_context != NULL) {
        new->pki_context = ssh_pki_ctx_dup(src->pki_context);
        if (new->pki_context == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    *dest = new;

    return 0;
}

/** @internal
 * @brief Set a key exchange algorithm list option on the session.
 *
 * Supports prefix modifiers: '+' to append, '-' to remove, '^' to prepend
 * to the default algorithm list.
 *
 * @param[in]  session  The SSH session.
 * @param[in]  algo     The algorithm type to configure.
 * @param[in]  list     The algorithm list string.
 * @param[out] place    Pointer to the string to store
 *                      the resulting algorithm list.
 *
 * @return  `SSH_OK` on success, `SSH_ERROR` on error.
 */
int ssh_options_set_algo(ssh_session session,
                         enum ssh_kex_types_e algo,
                         const char *list,
                         char **place)
{
    /* When the list start with +,-,^ the filtration of unknown algorithms
     * gets handled inside the helper functions, otherwise the list is taken
     * as it is. */
    char *p = (char *)list;

    if (algo < SSH_COMP_C_S) {
        if (list[0] == '+') {
            p = ssh_add_to_default_algos(algo, list+1);
        } else if (list[0] == '-') {
            p = ssh_remove_from_default_algos(algo, list+1);
        } else if (list[0] == '^') {
            p = ssh_prefix_default_algos(algo, list+1);
        }
    }

    if (p == list) {
        if (ssh_fips_mode()) {
            p = ssh_keep_fips_algos(algo, list);
        } else {
            p = ssh_keep_known_algos(algo, list);
        }
    }

    if (p == NULL) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                "Setting method: no allowed algorithm for method \"%s\" (%s)",
                ssh_kex_get_description(algo), list);
        return -1;
    }

    SAFE_FREE(*place);
    *place = p;

    return 0;
}

/*
 * Map a public ssh_options_e onto the internal config opcode whose parser
 * case applies it via ssh_options_set(). Used to mark a value as "seen" when
 * an application sets it explicitly, so later config-file processing does not
 * override it (OpenSSH "first obtained value wins" semantics).
 *
 * Returns SOC_UNKNOWN for options that must NOT be protected:
 *   - accumulative options (IdentityFile/CertificateFile and friends),
 *   - SSH_OPTIONS_HOST, the Host/Match lookup key that config HostName
 *     intentionally overrides during alias resolution,
 *   - operational settings such as log verbosity,
 *   - options that have no ssh_config equivalent,
 *   - getter-only options, which ssh_options_set() never accepts.
 */
static enum ssh_config_opcode_e ssh_opt_type_to_opcode(enum ssh_options_e type)
{
    switch (type) {
    case SSH_OPTIONS_PORT:
    case SSH_OPTIONS_PORT_STR:
        return SOC_PORT;
    case SSH_OPTIONS_USER:
        return SOC_USERNAME;
    case SSH_OPTIONS_KNOWNHOSTS:
        return SOC_KNOWNHOSTS;
    case SSH_OPTIONS_GLOBAL_KNOWNHOSTS:
        return SOC_GLOBALKNOWNHOSTSFILE;
    case SSH_OPTIONS_TIMEOUT:
        return SOC_TIMEOUT;
    case SSH_OPTIONS_CIPHERS_C_S:
    case SSH_OPTIONS_CIPHERS_S_C:
        return SOC_CIPHERS;
    case SSH_OPTIONS_COMPRESSION:
    case SSH_OPTIONS_COMPRESSION_C_S:
    case SSH_OPTIONS_COMPRESSION_S_C:
        return SOC_COMPRESSION;
    case SSH_OPTIONS_PROXYCOMMAND:
        return SOC_PROXYCOMMAND;
    case SSH_OPTIONS_PROXYJUMP:
        return SOC_PROXYJUMP;
    case SSH_OPTIONS_BINDADDR:
        return SOC_BINDADDRESS;
    case SSH_OPTIONS_STRICTHOSTKEYCHECK:
        return SOC_STRICTHOSTKEYCHECK;
    case SSH_OPTIONS_KEY_EXCHANGE:
        return SOC_KEXALGORITHMS;
    case SSH_OPTIONS_HOSTKEYS:
        return SOC_HOSTKEYALGORITHMS;
    case SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES:
        return SOC_PUBKEYACCEPTEDKEYTYPES;
    case SSH_OPTIONS_HMAC_C_S:
    case SSH_OPTIONS_HMAC_S_C:
        return SOC_MACS;
    case SSH_OPTIONS_GSSAPI_SERVER_IDENTITY:
        return SOC_GSSAPISERVERIDENTITY;
    case SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY:
        return SOC_GSSAPICLIENTIDENTITY;
    case SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS:
        return SOC_GSSAPIDELEGATECREDENTIALS;
    case SSH_OPTIONS_GSSAPI_KEY_EXCHANGE:
        return SOC_GSSAPIKEYEXCHANGE;
    case SSH_OPTIONS_GSSAPI_KEY_EXCHANGE_ALGS:
        return SOC_GSSAPIKEXALGORITHMS;
    case SSH_OPTIONS_PASSWORD_AUTH:
        return SOC_PASSWORDAUTHENTICATION;
    case SSH_OPTIONS_PUBKEY_AUTH:
        return SOC_PUBKEYAUTHENTICATION;
    case SSH_OPTIONS_KBDINT_AUTH:
        return SOC_KBDINTERACTIVEAUTHENTICATION;
    case SSH_OPTIONS_GSSAPI_AUTH:
        return SOC_GSSAPIAUTHENTICATION;
    case SSH_OPTIONS_PREFERRED_AUTHENTICATIONS:
        return SOC_PREFERRED_AUTHENTICATIONS;
    case SSH_OPTIONS_REKEY_DATA:
    case SSH_OPTIONS_REKEY_TIME:
        return SOC_REKEYLIMIT;
    case SSH_OPTIONS_RSA_MIN_SIZE:
        return SOC_REQUIRED_RSA_SIZE;
    case SSH_OPTIONS_IDENTITY_AGENT:
        return SOC_IDENTITYAGENT;
    case SSH_OPTIONS_IDENTITIES_ONLY:
        return SOC_IDENTITIESONLY;
    case SSH_OPTIONS_CONTROL_MASTER:
        return SOC_CONTROLMASTER;
    case SSH_OPTIONS_CONTROL_PATH:
        return SOC_CONTROLPATH;
    case SSH_OPTIONS_ADDRESS_FAMILY:
        return SOC_ADDRESSFAMILY;
    case SSH_OPTIONS_SERVER_ALIVE_INTERVAL:
        return SOC_SERVERALIVEINTERVAL;
    case SSH_OPTIONS_SERVER_ALIVE_COUNT_MAX:
        return SOC_SERVERALIVECOUNTMAX;
    case SSH_OPTIONS_BATCH_MODE:
        return SOC_BATCHMODE;
    case SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS:
        return SOC_NUMBER_OF_PASSWORD_PROMPTS;
    case SSH_OPTIONS_REQUEST_TTY:
        return SOC_REQUEST_TTY;
    case SSH_OPTIONS_ESCAPE_CHAR:
        return SOC_ESCAPE_CHAR;
    case SSH_OPTIONS_EXIT_ON_FORWARD_FAILURE:
        return SOC_EXIT_ON_FORWARD_FAILURE;
    case SSH_OPTIONS_FORWARD_AGENT:
    case SSH_OPTIONS_FORWARD_AGENT_SOCK_PATH:
        return SOC_FORWARD_AGENT;
    /*
     * Accumulative options append to a list instead of replacing a value, so
     * the "first value wins" precedence between config and the application does
     * not apply to them.
     */
    case SSH_OPTIONS_IDENTITY:
    case SSH_OPTIONS_ADD_IDENTITY:
    case SSH_OPTIONS_CERTIFICATE:
    case SSH_OPTIONS_PROXYJUMP_CB_LIST_APPEND:
    case SSH_OPTIONS_LOCAL_FORWARD:
    case SSH_OPTIONS_REMOTE_FORWARD:
    case SSH_OPTIONS_SEND_ENV:
    /*
     * SSH_OPTIONS_HOST carries the destination as given by the application,
     * which is OpenSSH's "host" (the Host/Match lookup key), not its
     * "hostname". Config HostName resolves that key to the real hostname and
     * must keep doing so. HostName has its own "first value wins" precedence
     * between config entries, enforced independently via seen[SOC_HOSTNAME]
     * while parsing the configuration.
     */
    case SSH_OPTIONS_HOST:
    /*
     * Operational settings that applications and frameworks routinely set on
     * their own, independent of the connection configuration. OpenSSH's config
     * parser notably does not let a previously-set value suppress LogLevel, so
     * we follow it and leave log verbosity unprotected.
     */
    case SSH_OPTIONS_LOG_VERBOSITY:
    case SSH_OPTIONS_LOG_VERBOSITY_STR:
    /*
     * Options with no OpenSSH ssh_config equivalent (or that are never applied
     * from a config file), so there is no config value that could override the
     * application's choice.
     */
    case SSH_OPTIONS_FD:
    case SSH_OPTIONS_SSH_DIR:
    case SSH_OPTIONS_SSH1:
    case SSH_OPTIONS_SSH2:
    case SSH_OPTIONS_TIMEOUT_USEC:
    case SSH_OPTIONS_COMPRESSION_LEVEL:
    case SSH_OPTIONS_NODELAY:
    case SSH_OPTIONS_PROCESS_CONFIG:
    case SSH_OPTIONS_PKI_CONTEXT:
    /*
     * Getter-only options: ssh_options_set() rejects them, so they never reach
     * the marking step. Listed to keep the switch exhaustive.
     */
    case SSH_OPTIONS_NEXT_IDENTITY:
    case SSH_OPTIONS_NEXT_LOCAL_FORWARD:
    case SSH_OPTIONS_NEXT_REMOTE_FORWARD:
    case SSH_OPTIONS_NEXT_SEND_ENV:
        return SOC_UNKNOWN;
    }

    return SOC_UNKNOWN;
}

/**
 * @brief This function can set all possible ssh options.
 *
 * @param  session An allocated SSH session structure.
 *
 * @param  type The option type to set. This could be one of the
 *              following:
 *
 *              - SSH_OPTIONS_HOST:
 *                The hostname or ip address to connect to. It can be also in
 *                the format of URI, containing also username, such as
 *                [username@]hostname. The IPv6 addresses can be enclosed
 *                within square braces, for example [::1]. The IPv4 address
 *                supports any format supported by OS. The hostname needs to be
 *                encoded to match RFC1035, so for IDN it needs to be encoded
 *                in punycode.
 *                (const char *).
 *
 *              - SSH_OPTIONS_PORT:
 *                The port to connect to (unsigned int).
 *
 *              - SSH_OPTIONS_PORT_STR:
 *                The port to connect to (const char *).
 *
 *              - SSH_OPTIONS_FD:
 *                The file descriptor to use (socket_t).\n
 *                \n
 *                If you wish to open the socket yourself for a reason
 *                or another, set the file descriptor and take care of closing
 *                it (this is new behavior in libssh 0.10).
 *                Don't forget to set the hostname as the hostname is used
 *                as a key in the known_host mechanism.
 *
 *              - SSH_OPTIONS_BINDADDR:
 *                The address to bind the client to (const char *).
 *
 *              - SSH_OPTIONS_USER:
 *                The username for authentication (const char *).\n
 *                \n
 *                If the value is NULL, the username is set to the
 *                default username.
 *
 *              - SSH_OPTIONS_SSH_DIR:
 *                Set the ssh directory (const char *,format string).\n
 *                \n
 *                If the value is NULL, the directory is set to the
 *                default ssh directory.\n
 *                \n
 *                The ssh directory is used for files like known_hosts
 *                and identity (private and public key). It may start
 *                with ~ which will be replaced by the user home
 *                directory.
 *
 *              - SSH_OPTIONS_KNOWNHOSTS:
 *                Set the known hosts file name (const char *,format string).\n
 *                \n
 *                If the value is NULL, the directory is set to the
 *                default known hosts file, normally
 *                ~/.ssh/known_hosts.\n
 *                \n
 *                The known hosts file is used to certify remote hosts
 *                are genuine. It may include "%d" which will be
 *                replaced by the user home directory.
 *
 *              - SSH_OPTIONS_GLOBAL_KNOWNHOSTS:
 *                Set the global known hosts file name (const char *,format string).\n
 *                \n
 *                If the value is NULL, the directory is set to the
 *                default global known hosts file, normally
 *                /etc/ssh/ssh_known_hosts.\n
 *                \n
 *                The known hosts file is used to certify remote hosts
 *                are genuine.
 *
 *              - SSH_OPTIONS_ADD_IDENTITY (or SSH_OPTIONS_IDENTITY):
 *                Add a new identity file (const char *, format string) to
 *                the identity list.\n
 *                \n
 *                By default id_rsa, id_ecdsa and id_ed25519 files are used.\n
 *                If libssh is built with FIDO2/U2F support, id_ecdsa_sk and\n
 *                id_ed25519_sk files are also used by default.\n
 *                \n
 *                The identity used to authenticate with public key will be
 *                prepended to the list.
 *                It may include "%s" which will be replaced by the
 *                user home directory.
 *
 *              - SSH_OPTIONS_CERTIFICATE:
 *                Add a new certificate file (const char *, format string) to
 *                the certificate list.\n
 *                \n
 *                By default id_rsa-cert.pub, id_ecdsa-cert.pub and
 *                id_ed25519-cert.pub files are used, when the underlying
 *                private key is present.\n
 *                \n
 *                The certificate itself can not be used to authenticate to
 *                remote server so it needs to be paired with private key
 *                (aka identity file) provided with separate option, from agent
 *                or from PKCS#11 token.
 *                It may include "%s" which will be replaced by the
 *                user home directory.
 *
 *              - SSH_OPTIONS_TIMEOUT:
 *                Set a timeout for the connection in seconds (long).
 *
 *              - SSH_OPTIONS_TIMEOUT_USEC:
 *                Set a timeout for the connection in micro seconds
 *                        (long).
 *
 *              - SSH_OPTIONS_SSH1:
 *                Deprecated
 *
 *              - SSH_OPTIONS_SSH2:
 *                Unused
 *
 *              - SSH_OPTIONS_LOG_VERBOSITY:
 *                Set the session logging verbosity (int).\n
 *                \n
 *                The verbosity of the messages. Every log smaller or
 *                equal to verbosity will be shown.
 *                - SSH_LOG_NOLOG: No logging
 *                - SSH_LOG_WARNING: Only warnings
 *                - SSH_LOG_PROTOCOL: High level protocol information
 *                - SSH_LOG_PACKET: Lower level protocol information, packet level
 *                - SSH_LOG_FUNCTIONS: Every function path
 *                The default is SSH_LOG_NOLOG.
 *
 *              - SSH_OPTIONS_LOG_VERBOSITY_STR:
 *                Set the session logging verbosity via a
 *                string that will be converted to a numerical
 *                value (e.g. "3") and interpreted according
 *                to the values of
 *                SSH_OPTIONS_LOG_VERBOSITY above (const
 *                char *).
 *
 *              - SSH_OPTIONS_CIPHERS_C_S:
 *                Set the symmetric cipher client to server (const char *,
 *                comma-separated list). The list can be prepended by +,-,^
 *                which can append, remove or move to the beginning
 *                (prioritizing) of the default list respectively. Giving an
 *                empty list after + and ^ will cause error.
 *
 *              - SSH_OPTIONS_CIPHERS_S_C:
 *                Set the symmetric cipher server to client (const char *,
 *                comma-separated list). The list can be prepended by +,-,^
 *                which can append, remove or move to the beginning
 *                (prioritizing) of the default list respectively. Giving an
 *                empty list after + and ^ will cause error.
 *
 *              - SSH_OPTIONS_KEY_EXCHANGE:
 *                Set the key exchange method to be used (const char *,
 *                comma-separated list). ex:
 *                "ecdh-sha2-nistp256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
 *                The list can be prepended by +,-,^ which will append,
 *                remove or move to the beginning (prioritizing) of the
 *                default list respectively. Giving an empty list
 *                after + and ^ will cause error.
 *
 *              - SSH_OPTIONS_HMAC_C_S:
 *                Set the Message Authentication Code algorithm client to server
 *                (const char *, comma-separated list). The list can be
 *                prepended by +,-,^ which will append, remove or move to
 *                the beginning (prioritizing) of the default list
 *                respectively. Giving an empty list after + and ^ will
 *                cause error.
 *
 *              - SSH_OPTIONS_HMAC_S_C:
 *                Set the Message Authentication Code algorithm server to client
 *                (const char *, comma-separated list). The list can be
 *                prepended by +,-,^ which will append, remove or move to
 *                the beginning (prioritizing) of the default list
 *                respectively. Giving an empty list after + and ^ will
 *                cause error.
 *
 *              - SSH_OPTIONS_HOSTKEYS:
 *                Set the preferred server host key types (const char *,
 *                comma-separated list). ex:
 *                "ssh-rsa,ecdh-sha2-nistp256". The list can be
 *                prepended by +,-,^ which will append, remove or move to
 *                the beginning (prioritizing) of the default list
 *                respectively. Giving an empty list after + and ^ will
 *                cause error.
 *
 *              - SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES:
 *                Set the preferred public key algorithms to be used for
 *                authentication (const char *, comma-separated list). ex:
 *                "ssh-rsa,rsa-sha2-256,ecdh-sha2-nistp256"
 *                The list can be prepended by +,-,^ which will append,
 *                remove or move to the beginning (prioritizing) of the
 *                default list respectively. Giving an empty list
 *                after + and ^ will cause error.
 *
 *              - SSH_OPTIONS_COMPRESSION_C_S:
 *                Set the compression to use for client to server
 *                communication (const char *, "yes", "no" or a specific
 *                algorithm name if needed ("zlib","zlib@openssh.com","none").
 *
 *              - SSH_OPTIONS_COMPRESSION_S_C:
 *                Set the compression to use for server to client
 *                communication (const char *, "yes", "no" or a specific
 *                algorithm name if needed ("zlib","zlib@openssh.com","none").
 *
 *              - SSH_OPTIONS_COMPRESSION:
 *                Set the compression to use for both directions
 *                communication (const char *, "yes", "no" or a specific
 *                algorithm name if needed ("zlib","zlib@openssh.com","none").
 *
 *              - SSH_OPTIONS_COMPRESSION_LEVEL:
 *                Set the compression level to use for zlib functions. (int,
 *                value from 1 to 9, 9 being the most efficient but slower).
 *
 *              - SSH_OPTIONS_STRICTHOSTKEYCHECK:
 *                Set the parameter StrictHostKeyChecking to control how
 *                unknown host keys are handled (int, SSH_STRICT_HOSTKEY_OFF,
 *                SSH_STRICT_HOSTKEY_YES, SSH_STRICT_HOSTKEY_ASK or
 *                SSH_STRICT_HOSTKEY_ACCEPT_NEW).
 *                Default: SSH_STRICT_HOSTKEY_ASK.
 *
 *              - SSH_OPTIONS_PROXYCOMMAND:
 *                Set the command to be executed in order to connect to
 *                server (const char *).
 *
 *              - SSH_OPTIONS_PROXYJUMP:
 *                Set the comma separated jump hosts in order to connect to
 *                server (const char *). Set to "none" to disable.
 *                Example:
 *                  "alice@127.0.0.1:5555,bob@127.0.0.2"
 *
 *                If environment variable OPENSSH_PROXYJUMP is set to 1 then proxyjump will be
 *                handled by the OpenSSH binary.
 *
 *              - SSH_OPTIONS_PROXYJUMP_CB_LIST_APPEND:
 *                Append the callbacks struct for a jump in order of
 *                SSH_OPTIONS_PROXYJUMP. Append as many times
 *                as the number of jumps (struct ssh_jump_callbacks_struct *).
 *
 *              - SSH_OPTIONS_GSSAPI_SERVER_IDENTITY
 *                Set it to specify the GSSAPI server identity that libssh
 *                should expect when connecting to the server (const char *).
 *
 *              - SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY
 *                Set it to specify the GSSAPI client identity that libssh
 *                should expect when connecting to the server (const char *).
 *
 *              - SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS
 *                Set it to specify that GSSAPI should delegate credentials
 *                to the server (int, 0 = false).
 *
 *              - SSH_OPTIONS_GSSAPI_KEY_EXCHANGE
 *                Set to true to allow GSSAPI key exchange (bool).
 *
 *              - SSH_OPTIONS_GSSAPI_KEY_EXCHANGE_ALGS
 *                Set the GSSAPI key exchange method to be used (const char *,
 *                comma-separated list). ex:
 *                "gss-curve25519-sha256-,gss-nistp256-sha256-"
 *                These will prefix the default algorithms if
 *                SSH_OPTIONS_GSSAPI_KEY_EXCHANGE is true.
 *
 *              - SSH_OPTIONS_PASSWORD_AUTH
 *                Set it if password authentication should be used
 *                in ssh_userauth_password(). (int, 0=false).
 *
 *              - SSH_OPTIONS_PUBKEY_AUTH
 *                Set the PubkeyAuthentication mode used by
 *                ssh_userauth_publickey_auto(),
 *                ssh_userauth_try_publickey(),
 *                ssh_userauth_publickey(), and ssh_userauth_agent().
 *                The default is SSH_PUBKEY_AUTH_ALL.
 *                (int, SSH_PUBKEY_AUTH_NO, SSH_PUBKEY_AUTH_ALL,
 *                SSH_PUBKEY_AUTH_UNBOUND or SSH_PUBKEY_AUTH_HOST_BOUND).
 *
 *              - SSH_OPTIONS_KBDINT_AUTH
 *                Set it if keyboard-interactive authentication should
 *                be used in ssh_userauth_kbdint(). (int, 0=false).
 *
 *              - SSH_OPTIONS_GSSAPI_AUTH
 *                Set it if gssapi authentication should be used
 *                in ssh_userauth_gssapi(). (int, 0=false).
 *
 *              - SSH_OPTIONS_NODELAY
 *                Set it to disable Nagle's Algorithm (TCP_NODELAY) on the
 *                session socket. (int, 0=false)
 *
 *              - SSH_OPTIONS_PROCESS_CONFIG
 *                Set it to false to disable automatic processing of per-user
 *                and system-wide OpenSSH configuration files. LibSSH
 *                automatically uses these configuration files unless
 *                you provide it with this option or with different file (bool).
 *
 *              - SSH_OPTIONS_REKEY_DATA
 *                Set the data limit that can be transferred with a single
 *                key in bytes. RFC 4253 Section 9 recommends 1GB of data, while
 *                RFC 4344 provides more specific restrictions, that are applied
 *                automatically. When specified, the lower value will be used.
 *                (uint64_t, 0=default)
 *
 *              - SSH_OPTIONS_REKEY_TIME
 *                Set the time limit for a session before initializing a rekey
 *                in seconds. RFC 4253 Section 9 recommends one hour.
 *                (uint32_t, 0=off)
 *
 *              - SSH_OPTIONS_RSA_MIN_SIZE
 *                Set the minimum RSA key size in bits to be accepted by the
 *                client for both authentication and hostkey verification.
 *                The values under 1024 bits are not accepted even with this
 *                configuration option as they are considered completely broken.
 *                Setting 0 will revert the value to defaults.
 *                Default is 3072 bits or 2048 bits in FIPS mode.
 *                (int)
 *
 *              - SSH_OPTIONS_IDENTITY_AGENT
 *                Set the path to the SSH agent socket. If unset, the
 *                SSH_AUTH_SOCK environment is consulted.
 *                (const char *)
 *
 *              - SSH_OPTIONS_IDENTITIES_ONLY
 *                Use only keys specified in the SSH config, even if agent
 *                offers more.
 *                (bool)
 *
 *              - SSH_OPTIONS_CONTROL_MASTER
 *                Set the option to enable the sharing of multiple sessions over a
 *                single network connection using connection multiplexing (int).
 *
 *                The possible options are among the following:
 *                 - SSH_CONTROL_MASTER_AUTO: enable connection sharing if possible
 *                 - SSH_CONTROL_MASTER_YES: enable connection sharing unconditionally
 *                 - SSH_CONTROL_MASTER_ASK: ask for confirmation if connection sharing is to be enabled
 *                 - SSH_CONTROL_MASTER_AUTOASK: enable connection sharing if possible,
 *                                               but ask for confirmation
 *                 - SSH_CONTROL_MASTER_NO: disable connection sharing unconditionally
 *
 *                The default is SSH_CONTROL_MASTER_NO.
 *
 *              - SSH_OPTIONS_CONTROL_PATH
 *                Set the path to the control socket used for connection sharing.
 *                Set to "none" to disable connection sharing.
 *                (const char *)
 *
 *              - SSH_OPTIONS_PKI_CONTEXT
 *                Attach a previously created generic PKI context to the
 *                session. This allows supplying per-session PKI
 *                configuration options for PKI operations.
 *                All fields from the user's context are copied to the session's
 *                own context. The user retains ownership of the original
 *                context and can free it after this call.
 *                (ssh_pki_ctx)
 *
 *              - SSH_OPTIONS_ADDRESS_FAMILY
 *                Specify which address family to use when connecting.
 *
 *                Possible options:
 *                 - SSH_ADDRESS_FAMILY_ANY: use any address family
 *                 - SSH_ADDRESS_FAMILY_INET: IPv4 only
 *                 - SSH_ADDRESS_FAMILY_INET6: IPv6 only
 *
 *              - SSH_OPTIONS_PREFERRED_AUTHENTICATIONS
 *                Set the preferred authentication method(s) to use.
 *                This value is parsed from the configuration file and stored
 *                for the calling application to read; libssh does not
 *                automatically reorder authentication methods based on this
 *                setting.
 *                (string)
 *
 *              - SSH_OPTIONS_BATCH_MODE
 *                If set to true, indicates that the application is running
 *                non-interactively and must not prompt the user. The
 *                application is responsible for skipping password
 *                authentication and keyboard-interactive authentication,
 *                and for returning failure from passphrase callbacks instead
 *                of prompting the user. Use ssh_options_get_int() with
 *                SSH_OPTIONS_BATCH_MODE to read back this value after
 *                parsing a configuration file.
 *                Note that this value is parsed from the configuration file
 *                and stored for the calling application to read; libssh does
 *                not automatically change its behavior based on this setting.
 *                (bool)
 *
 *              - SSH_OPTIONS_SERVER_ALIVE_INTERVAL
 *                Set the time in seconds after which the client will send a
 *                keepalive message to the server if no data has been received.
 *                OpenSSH default is 0 (disabled). The value must be a
 *                non-negative integer. Setting 0 disables the keepalive
 *                mechanism. Note that this value is parsed from the
 *                configuration file and stored for the calling application to
 *                read; libssh does not automatically send keepalive messages
 *                based on this setting.
 *                (int)
 *
 *              - SSH_OPTIONS_SERVER_ALIVE_COUNT_MAX
 *                Set the maximum number of consecutive unanswered keepalive
 *                probes allowed before the client considers the server
 *                unresponsive. OpenSSH default is 3. The value must be a
 *                non-negative integer. Setting 0 means no keepalive probes
 *                are tolerated (immediate timeout). Note that this value is
 *                parsed from the configuration file and stored for the
 *                calling application to read; libssh does not automatically
 *                enforce keepalive timeouts based on this setting.
 *                (int)
 *
 *              - SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS
 *                Set the maximum number of password prompts before giving up.
 *                OpenSSH default is 3. The value must be a positive integer
 *                (>= 1). Passing NULL or a value <= 0 is rejected.
 *                When read via ssh_options_get_int(), 0 means "not configured"
 *                and the CLI will use the default of 3.
 *                Note that this value is parsed from the configuration file
 *                and stored for the calling application to read; libssh does
 *                not automatically limit password prompts based on this setting.
 *                (int)
 *
 *              - SSH_OPTIONS_REQUEST_TTY
 *                Set whether to request a pseudo-terminal for the session.
 *                Accepted values are SSH_REQUEST_TTY_NO (never),
 *                SSH_REQUEST_TTY_YES (always),
 *                SSH_REQUEST_TTY_AUTO (request on login),
 *                and SSH_REQUEST_TTY_FORCE (always, even when a command is
 *                specified). Note that this value is parsed from the
 *                configuration file and stored for the calling application to
 *                read; libssh does not automatically request a PTY based on
 *                this setting.
 *                (int)
 *
 *              - SSH_OPTIONS_ESCAPE_CHAR
 *                Set the escape character for the session.
 *                OpenSSH default is '~'. Accepted values are -1 (none,
 *                escape sequences disabled) or a single byte value
 *                in the range 1-255 for a custom escape character.
 *                In the configuration file, the value may be specified
 *                as a single character ("~"), as "^X" notation for
 *                control characters ("^C" for Ctrl-C), or as "none"
 *                to disable escape sequences.
 *                Passing NULL, 0, or a value less than -1 or greater
 *                than 255 is rejected.
 *                When read via ssh_options_get_int(), 0 means "not
 *                configured" and the CLI will use the default of '~'.
 *                Note that this value is parsed from the configuration
 *                file and stored for the calling application to read;
 *                libssh does not automatically change the escape
 *                character based on this setting.
 *                (int)
 *              - SSH_OPTIONS_EXIT_ON_FORWARD_FAILURE
 *                If set to true, indicates that the SSH session should
 *                terminate if it cannot set up all requested local and remote
 *                port forwardings, for example if the client or server is
 *                unable to bind and listen on a specified port. Note that
 *                this does not apply to connections made over port forwardings
 *                and will not cause the session to exit if TCP connections to
 *                the ultimate forwarding destination fail.
 *                This value is parsed from the configuration file and stored
 *                for the calling application to read; libssh does not
 *                automatically terminate the session based on this setting.
 *                (bool)
 *              - SSH_OPTIONS_FORWARD_AGENT
 *                If set to true, indicates that the local SSH agent
 *                connection should be forwarded to the remote machine.
 *                This value is parsed from the configuration file and stored
 *                for the calling application to read; libssh does not
 *                automatically request agent forwarding based on this
 *                setting.
 *                (bool)
 *              - SSH_OPTIONS_FORWARD_AGENT_SOCK_PATH
 *                Set the path to the local SSH agent socket to use for
 *                agent forwarding. The value may be a literal socket path or
 *                the name of an environment variable (starting with '$') that
 *                holds the path. If unset, the SSH_AUTH_SOCK environment is
 *                consulted. The socket path is only used when agent
 *                forwarding is enabled; a "$VAR" reference is stored verbatim
 *                at config-parse time and expanded only after login, at
 *                session time.
 *                This value is parsed from the configuration file and stored
 *                for the calling application to read; libssh does not
 *                automatically use this socket for agent forwarding based on
 *                this setting.
 *                (const char *)
 *              - SSH_OPTIONS_SEND_ENV
 *                Append one environment variable name pattern to the list of
 *                patterns to send to the server. Multiple calls accumulate
 *                patterns. If the value has a leading '-' (for example
 *                "-LANG"), the matching pattern is removed from the list
 *                instead of added. Removing a pattern that does not exist
 *                in the list is not an error and the existing patterns are
 *                not affected. To iterate the list, use SSH_OPTIONS_SEND_ENV
 *                followed by SSH_OPTIONS_NEXT_SEND_ENV in ssh_options_get().
 *                Note that this value is parsed from the configuration file
 *                and stored for the calling application to read; libssh does
 *                not automatically send environment variables based on this
 *                setting.
 *                (const char *)
 *
 *              - SSH_OPTIONS_LOCAL_FORWARD
 *                Append one local forwarding specification to the list.
 *                The format is "<bind_spec> <remote_spec>", for example,
 *                "8080 web:80" or "0.0.0.0:9090 db:3306". Multiple calls
 *                accumulate entries. To iterate the list, use
 *                SSH_OPTIONS_LOCAL_FORWARD followed by
 *                SSH_OPTIONS_NEXT_LOCAL_FORWARD in ssh_options_get().
 *                Note that this value is parsed from the configuration
 *                file and stored for the calling application to read;
 *                libssh does not automatically set up local forwarding
 *                based on this setting.
 *                (const char *)
 *
 *              - SSH_OPTIONS_REMOTE_FORWARD
 *                Append one remote forwarding specification to the list.
 *                The format is "<bind_spec> <target_spec>", for example,
 *                "8080 localhost:3000" or "0.0.0.0:9090 db:3306". Multiple
 *                calls accumulate entries. To iterate the list, use
 *                SSH_OPTIONS_REMOTE_FORWARD followed by
 *                SSH_OPTIONS_NEXT_REMOTE_FORWARD in ssh_options_get().
 *                Note that this value is parsed from the configuration
 *                file and stored for the calling application to read;
 *                libssh does not automatically set up remote forwarding
 *                based on this setting.
 *                (const char *)
 *
 * @param  value The value to set. This is a generic pointer and the
 *               datatype which is used should be set according to the
 *               type set.
 *
 * @return       0 on success, < 0 on error.
 *
 * @warning      When the option value to set is represented via a pointer
 *               (e.g const char * in case of strings, ssh_key in case of a
 *               libssh key), the value parameter should be that pointer.
 *               Do NOT pass a pointer to a pointer (const char **, ssh_key *)
 *
 * @warning      When the option value to set is not a pointer (e.g int,
 *               unsigned int, bool, long), the value parameter should be
 *               a pointer to the location storing the value to set (int *,
 *               unsigned int *, bool *, long *)
 *
 * @warning      If the value parameter has an invalid type (e.g if its not a
 *               pointer when it should have been a pointer, or if its a pointer
 *               to a pointer when it should have just been a pointer), then the
 *               behaviour is undefined.
 */
int ssh_options_set(ssh_session session,
                    enum ssh_options_e type,
                    const void *value)
{
    const char *v = NULL;
    char *p = NULL, *q = NULL;
    long int i;
    unsigned int u;
    int rc;
    char **wanted_methods = session->opts.wanted_methods;
    struct ssh_jump_callbacks_struct *j = NULL;
    enum ssh_config_opcode_e opcode;

    if (session == NULL) {
        return -1;
    }

    switch (type) {
        case SSH_OPTIONS_HOST:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else if (session->opts.config_hostname_only) {
                /* HostName values are plain hostnames, not user@host URIs */
                SAFE_FREE(session->opts.host);
                session->opts.host = strdup(value);
                if (session->opts.host == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            } else {
                char *username = NULL, *hostname = NULL;
                char *strict_hostname = NULL;
                char *normalized = NULL;

                /* Non-strict parse: reject shell metacharacters */
                rc = ssh_config_parse_uri(value,
                                          &username,
                                          &hostname,
                                          NULL,
                                          true,
                                          false);
                if (rc != SSH_OK || hostname == NULL) {
                    SAFE_FREE(username);
                    SAFE_FREE(hostname);
                    ssh_set_error_invalid(session);
                    return -1;
                }

                /* Non-strict passed: set username and originalhost */
                if (username != NULL) {
                    SAFE_FREE(session->opts.username);
                    session->opts.username = username;
                }
                SAFE_FREE(session->opts.config_hostname);
                SAFE_FREE(session->opts.originalhost);
                session->opts.originalhost = hostname;

                /* Strict parse: set host only if valid hostname or IP */
                rc = ssh_normalize_loose_ip(value, &normalized);
                if (rc == -1) {
                    /* Error */
                    SAFE_FREE(username);
                    ssh_set_error_oom(session);
                    return -1;
                }
                rc = ssh_config_parse_uri(
                    (normalized != NULL) ? normalized : value,
                    NULL,
                    &strict_hostname,
                    NULL,
                    true,
                    true);
                SAFE_FREE(normalized);

                if (rc != SSH_OK || strict_hostname == NULL) {
                    SAFE_FREE(session->opts.host);
                    SAFE_FREE(strict_hostname);
                } else {
                    SAFE_FREE(session->opts.host);
                    session->opts.host = strict_hostname;
                }
            }
            break;
        case SSH_OPTIONS_PORT:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                if (*x <= 0 || *x > 65535) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.port = *x;
            }
            break;
        case SSH_OPTIONS_PORT_STR:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                q = strdup(v);
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                i = strtol(q, &p, 10);
                if (q == p || *p != '\0') {
                    SSH_LOG(SSH_LOG_DEBUG, "No port number was parsed");
                    SAFE_FREE(q);
                    return -1;
                }
                SAFE_FREE(q);
                if (i <= 0 || i > 65535) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.port = i;
            }
            break;
        case SSH_OPTIONS_FD:
            if (value == NULL) {
                session->opts.fd = SSH_INVALID_SOCKET;
                ssh_set_error_invalid(session);
                return -1;
            } else {
                socket_t *x = (socket_t *) value;
                if (*x < 0) {
                    session->opts.fd = SSH_INVALID_SOCKET;
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.fd = *x & 0xffff;
            }
            break;
        case SSH_OPTIONS_BINDADDR:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }

            q = strdup(v);
            if (q == NULL) {
                return -1;
            }
            SAFE_FREE(session->opts.bindaddr);
            session->opts.bindaddr = q;
            break;
        case SSH_OPTIONS_USER:
            v = value;
            SAFE_FREE(session->opts.username);
            if (v == NULL) {
                q = ssh_get_local_username();
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                session->opts.username = q;
            } else if (v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else { /* username provided */
                session->opts.username = strdup(value);
                if (session->opts.username == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                rc = ssh_check_username_syntax(session->opts.username);
                if (rc != SSH_OK) {
                    ssh_set_error_invalid(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_SSH_DIR:
            v = value;
            SAFE_FREE(session->opts.sshdir);
            if (v == NULL) {
                session->opts.sshdir = ssh_path_expand_tilde("~/.ssh");
                if (session->opts.sshdir == NULL) {
                    return -1;
                }
            } else if (v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                session->opts.sshdir = ssh_path_expand_tilde(v);
                if (session->opts.sshdir == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_IDENTITY:
        case SSH_OPTIONS_ADD_IDENTITY: {
            struct ssh_iterator *id_it = NULL;

            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }
            q = strdup(v);
            if (q == NULL) {
                return -1;
            }
            /* Deduplicate: skip if the same path is already in the list */
            for (id_it = ssh_list_get_iterator(session->opts.identity_non_exp);
                 id_it != NULL; id_it = id_it->next) {
                int cmp = strcmp(ssh_iterator_value(char *, id_it), q);
                if (cmp == 0) {
                    free(q);
                    return 0;
                }
            }
            if (session->opts.exp_flags & SSH_OPT_EXP_FLAG_IDENTITY) {
                rc = ssh_list_append(session->opts.identity_non_exp, q);
            } else {
                rc = ssh_list_prepend(session->opts.identity_non_exp, q);
            }
            if (rc < 0) {
                free(q);
                return -1;
            }
            break;
        }
        case SSH_OPTIONS_CERTIFICATE: {
            struct ssh_iterator *cert_it = NULL;

            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }
            q = strdup(v);
            if (q == NULL) {
                return -1;
            }
            /* Allocate on first use (no longer pre-allocated in ssh_new()) */
            if (session->opts.certificate_non_exp == NULL) {
                session->opts.certificate_non_exp = ssh_list_new();
                if (session->opts.certificate_non_exp == NULL) {
                    free(q);
                    return -1;
                }
            }

            /* Deduplicate: skip if the same path is already in the list */
            for (cert_it = ssh_list_get_iterator(session->opts.certificate_non_exp);
                 cert_it != NULL; cert_it = cert_it->next) {
                int cmp = strcmp(ssh_iterator_value(char *, cert_it), q);
                if (cmp == 0) {
                    free(q);
                    return 0;
                }
            }
            rc = ssh_list_append(session->opts.certificate_non_exp, q);
            if (rc < 0) {
                free(q);
                return -1;
            }
            break;
        }
        case SSH_OPTIONS_KNOWNHOSTS:
            v = value;
            SAFE_FREE(session->opts.knownhosts);
            if (v == NULL) {
                /* The default value will be set by the ssh_options_apply() */
            } else if (v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                session->opts.knownhosts = strdup(v);
                if (session->opts.knownhosts == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                session->opts.exp_flags &= ~SSH_OPT_EXP_FLAG_KNOWNHOSTS;
            }
            break;
        case SSH_OPTIONS_GLOBAL_KNOWNHOSTS:
            v = value;
            SAFE_FREE(session->opts.global_knownhosts);
            if (v == NULL) {
                session->opts.global_knownhosts =
                    strdup(GLOBAL_CONF_DIR "/ssh_known_hosts");
                if (session->opts.global_knownhosts == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            } else if (v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                session->opts.global_knownhosts = strdup(v);
                if (session->opts.global_knownhosts == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                session->opts.exp_flags &= ~SSH_OPT_EXP_FLAG_GLOBAL_KNOWNHOSTS;
            }
            break;
        case SSH_OPTIONS_TIMEOUT:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                long *x = (long *) value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.timeout = *x & 0xffffffffU;
            }
            break;
        case SSH_OPTIONS_TIMEOUT_USEC:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                long *x = (long *) value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.timeout_usec = *x & 0xffffffffU;
            }
            break;
        case SSH_OPTIONS_SSH1:
            break;
        case SSH_OPTIONS_SSH2:
            break;
        case SSH_OPTIONS_LOG_VERBOSITY:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->common.log_verbosity = *x & 0xffffU;
                ssh_set_log_level(*x & 0xffffU);
            }
            break;
        case SSH_OPTIONS_LOG_VERBOSITY_STR:
            v = value;
            if (v == NULL || v[0] == '\0') {
                session->common.log_verbosity = 0;
                ssh_set_error_invalid(session);
                return -1;
            } else {
                q = strdup(v);
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                i = strtol(q, &p, 10);
                if (q == p) {
                    SSH_LOG(SSH_LOG_DEBUG, "No log verbositiy was parsed");
                    SAFE_FREE(q);
                    return -1;
                }
                SAFE_FREE(q);
                if (i < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->common.log_verbosity = i & 0xffffU;
                ssh_set_log_level(i & 0xffffU);
            }
            break;
        case SSH_OPTIONS_CIPHERS_C_S:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                rc = ssh_options_set_algo(session,
                                          SSH_CRYPT_C_S,
                                          v,
                                          &wanted_methods[SSH_CRYPT_C_S]);
                if (rc < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_CIPHERS_S_C:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                rc = ssh_options_set_algo(session,
                                          SSH_CRYPT_S_C,
                                          v,
                                          &wanted_methods[SSH_CRYPT_S_C]);
                if (rc < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_KEY_EXCHANGE:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                rc = ssh_options_set_algo(session,
                                          SSH_KEX,
                                          v,
                                          &wanted_methods[SSH_KEX]);
                if (rc < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_HOSTKEYS:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                rc = ssh_options_set_algo(session,
                                          SSH_HOSTKEYS,
                                          v,
                                          &wanted_methods[SSH_HOSTKEYS]);
                if (rc < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                rc = ssh_options_set_algo(session,
                                          SSH_HOSTKEYS,
                                          v,
                                          &session->opts.pubkey_accepted_types);
                if (rc < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_HMAC_C_S:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                rc = ssh_options_set_algo(session,
                                          SSH_MAC_C_S,
                                          v,
                                          &wanted_methods[SSH_MAC_C_S]);
                if (rc < 0)
                    return -1;
            }
            break;
         case SSH_OPTIONS_HMAC_S_C:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                rc = ssh_options_set_algo(session,
                                          SSH_MAC_S_C,
                                          v,
                                          &wanted_methods[SSH_MAC_S_C]);
                if (rc < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_COMPRESSION_C_S:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                const char *tmp = v;
                if (strcasecmp(value, "yes") == 0){
                    tmp = "zlib@openssh.com,none";
                } else if (strcasecmp(value, "no") == 0){
                    tmp = "none,zlib@openssh.com";
                }
                rc = ssh_options_set_algo(session,
                                          SSH_COMP_C_S,
                                          tmp,
                                          &wanted_methods[SSH_COMP_C_S]);
                if (rc < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_COMPRESSION_S_C:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                const char *tmp = v;
                if (strcasecmp(value, "yes") == 0){
                    tmp = "zlib@openssh.com,none";
                } else if (strcasecmp(value, "no") == 0){
                    tmp = "none,zlib@openssh.com";
                }

                rc = ssh_options_set_algo(session,
                                          SSH_COMP_S_C,
                                          tmp,
                                          &wanted_methods[SSH_COMP_S_C]);
                if (rc < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_COMPRESSION:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }
            if(ssh_options_set(session,SSH_OPTIONS_COMPRESSION_C_S, v) < 0)
                return -1;
            if(ssh_options_set(session,SSH_OPTIONS_COMPRESSION_S_C, v) < 0)
                return -1;
            break;
        case SSH_OPTIONS_COMPRESSION_LEVEL:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *)value;
                if (*x < 1 || *x > 9) {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                session->opts.compressionlevel = *x & 0xff;
            }
            break;
        case SSH_OPTIONS_STRICTHOSTKEYCHECK:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                int mode = *x;

                switch (mode) {
                case SSH_STRICT_HOSTKEY_OFF:
                case SSH_STRICT_HOSTKEY_YES:
                case SSH_STRICT_HOSTKEY_ASK:
                case SSH_STRICT_HOSTKEY_ACCEPT_NEW:
                    session->opts.StrictHostKeyChecking = mode;
                    break;
                default:
                    /* Preserve the legacy low-byte "non-zero means yes"
                     * normalization.
                     */
                    session->opts.StrictHostKeyChecking =
                        (mode & 0xff) > 0 ? SSH_STRICT_HOSTKEY_YES
                                          : SSH_STRICT_HOSTKEY_OFF;
                    break;
                }
            }
            break;
        case SSH_OPTIONS_PROXYCOMMAND:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                SAFE_FREE(session->opts.ProxyCommand);
                /* Setting the command to 'none' disables this option. */
                rc = strcasecmp(v, "none");
                if (rc != 0) {
                    q = strdup(v);
                    if (q == NULL) {
                        return -1;
                    }
                    session->opts.ProxyCommand = q;
                    session->opts.exp_flags &= ~SSH_OPT_EXP_FLAG_PROXYCOMMAND;
                }
            }
            break;
        case SSH_OPTIONS_PROXYJUMP:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                rc = ssh_config_parse_proxy_jump(session, v, true);
                if (rc != SSH_OK) {
                    return SSH_ERROR;
                }
            }
            break;
        case SSH_OPTIONS_PROXYJUMP_CB_LIST_APPEND:
            j = (struct ssh_jump_callbacks_struct *)value;
            if (j == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                /* Allocate on first use (no longer pre-allocated in ssh_new()) */
                if (session->opts.proxy_jumps_user_cb == NULL) {
                    session->opts.proxy_jumps_user_cb = ssh_list_new();
                    if (session->opts.proxy_jumps_user_cb == NULL) {
                        ssh_set_error_oom(session);
                        return SSH_ERROR;
                    }
                }
                rc = ssh_list_prepend(session->opts.proxy_jumps_user_cb, j);
                if (rc != SSH_OK) {
                    ssh_set_error_oom(session);
                    return SSH_ERROR;
                }
            }
            break;
        case SSH_OPTIONS_GSSAPI_SERVER_IDENTITY:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                SAFE_FREE(session->opts.gss_server_identity);
                session->opts.gss_server_identity = strdup(v);
                if (session->opts.gss_server_identity == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                SAFE_FREE(session->opts.gss_client_identity);
                session->opts.gss_client_identity = strdup(v);
                if (session->opts.gss_client_identity == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int x = *(int *)value;

                session->opts.gss_delegate_creds = (x & 0xff);
            }
            break;
#ifdef WITH_GSSAPI
        case SSH_OPTIONS_GSSAPI_KEY_EXCHANGE:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                bool *x = (bool *)value;
                session->opts.gssapi_key_exchange = *x;
            }
            break;
        case SSH_OPTIONS_GSSAPI_KEY_EXCHANGE_ALGS:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                /* Check if algorithms are supported */
                char *ret =
                    ssh_find_all_matching(GSSAPI_KEY_EXCHANGE_SUPPORTED, v);
                if (ret == NULL) {
                    ssh_set_error(session,
                                  SSH_FATAL,
                                  "GSSAPI key exchange algorithms not "
                                  "supported or invalid");
                    return -1;
                }
                SAFE_FREE(session->opts.gssapi_key_exchange_algs);
                session->opts.gssapi_key_exchange_algs = ret;
            }
            break;
#endif
        case SSH_OPTIONS_PASSWORD_AUTH:
        case SSH_OPTIONS_PUBKEY_AUTH:
        case SSH_OPTIONS_KBDINT_AUTH:
        case SSH_OPTIONS_GSSAPI_AUTH:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int x = *(int *)value;
                u = type == SSH_OPTIONS_PASSWORD_AUTH ?
                    SSH_OPT_FLAG_PASSWORD_AUTH:
                    type == SSH_OPTIONS_PUBKEY_AUTH ?
                        SSH_OPT_FLAG_PUBKEY_AUTH:
                        type == SSH_OPTIONS_KBDINT_AUTH ?
                            SSH_OPT_FLAG_KBDINT_AUTH:
                            SSH_OPT_FLAG_GSSAPI_AUTH;
                if (x != 0) {
                    session->opts.flags |= u;
                } else {
                    session->opts.flags &= ~u;
                }
                if (type == SSH_OPTIONS_PUBKEY_AUTH) {
                    /*
                     * Keep the legacy enabled/disabled auth flag semantics in
                     * sync above while also storing the selected
                     * PubkeyAuthentication mode here.
                     */
                    switch (x) {
                    case SSH_PUBKEY_AUTH_NO:
                    case SSH_PUBKEY_AUTH_ALL:
                    case SSH_PUBKEY_AUTH_UNBOUND:
                    case SSH_PUBKEY_AUTH_HOST_BOUND:
                        session->opts.pubkey_auth = x;
                        break;
                    default:
                        /* Preserve the legacy non-zero "yes" normalization
                         * here so callers passing -1 still land on
                         * SSH_PUBKEY_AUTH_ALL.
                         */
                        session->opts.pubkey_auth = SSH_PUBKEY_AUTH_ALL;
                        break;
                    }
                }
            }
            break;
        case SSH_OPTIONS_NODELAY:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                session->opts.nodelay = (*x & 0xff) > 0 ? 1 : 0;
            }
            break;
        case SSH_OPTIONS_PROCESS_CONFIG:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                bool *x = (bool *)value;
                session->opts.config_processed = !(*x);
            }
            break;
        case SSH_OPTIONS_REKEY_DATA:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                uint64_t *x = (uint64_t *)value;
                session->opts.rekey_data = *x;
            }
            break;
        case SSH_OPTIONS_REKEY_TIME:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                uint32_t *x = (uint32_t *)value;
                if (*x > UINT32_MAX / 1000) {
                    ssh_set_error(session, SSH_REQUEST_DENIED,
                                  "The provided value (%" PRIu32 ") for rekey"
                                  " time is too large", *x);
                    return -1;
                }
                session->opts.rekey_time = (*x) * 1000;
            }
            break;
        case SSH_OPTIONS_RSA_MIN_SIZE:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *)value;

                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                /* (*x == 0) is allowed as it is used to revert to default */

                if (*x > 0 && *x < RSA_MIN_KEY_SIZE) {
                    ssh_set_error(session,
                                  SSH_REQUEST_DENIED,
                                  "The provided value (%d) for minimal RSA key "
                                  "size is too small. Use at least %d bits.",
                                  *x,
                                  RSA_MIN_KEY_SIZE);
                    return -1;
                }
                session->opts.rsa_min_size = *x;
            }
            break;
        case SSH_OPTIONS_IDENTITY_AGENT:
            v = value;
            SAFE_FREE(session->opts.agent_socket);
            if (v == NULL) {
                /* The default value will be set by the ssh_options_apply() */
            } else if (v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                session->opts.agent_socket = ssh_path_expand_tilde(v);
                if (session->opts.agent_socket == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_IDENTITIES_ONLY:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                bool *x = (bool *)value;
                session->opts.identities_only = *x;
            }
            break;
        case SSH_OPTIONS_CONTROL_MASTER:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                if (*x < SSH_CONTROL_MASTER_NO || *x > SSH_CONTROL_MASTER_AUTOASK) {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                session->opts.control_master = *x;
            }
            break;
        case SSH_OPTIONS_CONTROL_PATH:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                SAFE_FREE(session->opts.control_path);
                rc = strcasecmp(v, "none");
                if (rc != 0) {
                    session->opts.control_path = ssh_path_expand_tilde(v);
                    if (session->opts.control_path == NULL) {
                        ssh_set_error_oom(session);
                        return -1;
                    }
                    session->opts.exp_flags &= ~SSH_OPT_EXP_FLAG_CONTROL_PATH;
                }
            }
            break;
        case SSH_OPTIONS_PKI_CONTEXT:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            }

            SSH_PKI_CTX_FREE(session->pki_context);

            session->pki_context = ssh_pki_ctx_dup((const ssh_pki_ctx)value);
            if (session->pki_context == NULL) {
                ssh_set_error_oom(session);
                return -1;
            }
            break;
        case SSH_OPTIONS_ADDRESS_FAMILY:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *)value;
                if (*x < SSH_ADDRESS_FAMILY_ANY ||
                    *x > SSH_ADDRESS_FAMILY_INET6) {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                session->opts.address_family = *x;
            }
            break;
        case SSH_OPTIONS_BATCH_MODE:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                bool *x = (bool *)value;
                session->opts.batch_mode = *x;
            }
            break;
        case SSH_OPTIONS_SERVER_ALIVE_INTERVAL:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *)value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                session->opts.server_alive_interval = *x;
            }
            break;
        case SSH_OPTIONS_SERVER_ALIVE_COUNT_MAX:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *)value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                session->opts.server_alive_count_max = *x;
            }
            break;
        case SSH_OPTIONS_ESCAPE_CHAR:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *)value;
                if (*x == 0 || *x < -1 || *x > 255) {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                session->opts.escape_char = *x;
            }
            break;
        case SSH_OPTIONS_LOCAL_FORWARD:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }
            q = strdup(v);
            if (q == NULL) {
                ssh_set_error_oom(session);
                return -1;
            }
            /* Allocate on first use (no longer pre-allocated in ssh_new()) */
            if (session->opts.local_forward == NULL) {
                session->opts.local_forward = ssh_list_new();
                if (session->opts.local_forward == NULL) {
                    free(q);
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            rc = ssh_list_append(session->opts.local_forward, q);
            if (rc < 0) {
                free(q);
                ssh_set_error_oom(session);
                return -1;
            }
            break;
        case SSH_OPTIONS_REMOTE_FORWARD:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }
            q = strdup(v);
            if (q == NULL) {
                ssh_set_error_oom(session);
                return -1;
            }
            /* Lazy allocation: allocate list on first use */
            if (session->opts.remote_forward == NULL) {
                session->opts.remote_forward = ssh_list_new();
                if (session->opts.remote_forward == NULL) {
                    free(q);
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            rc = ssh_list_append(session->opts.remote_forward, q);
            if (rc < 0) {
                free(q);
                ssh_set_error_oom(session);
                return -1;
            }
            break;
        case SSH_OPTIONS_PREFERRED_AUTHENTICATIONS:
            v = value;
            SAFE_FREE(session->opts.preferred_authentications);
            if (v != NULL) {
                if (v[0] == '\0') {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                session->opts.preferred_authentications = strdup(v);
                if (session->opts.preferred_authentications == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *)value;
                if (*x <= 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                session->opts.number_of_password_prompts = *x;
            }
            break;
        case SSH_OPTIONS_REQUEST_TTY:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *)value;
                if (*x < SSH_REQUEST_TTY_NO || *x > SSH_REQUEST_TTY_FORCE) {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                session->opts.request_tty = *x;
            }
            break;
        case SSH_OPTIONS_SEND_ENV:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }
            /* A leading '-' removes the pattern from the list */
            if (v[0] == '-') {
                const char *pattern = NULL;
                const char *env_value = NULL;
                struct ssh_iterator *it = NULL;
                struct ssh_iterator *next = NULL;
                int cmp = 0;

                pattern = v + 1;
                if (pattern[0] == '\0') {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                it = ssh_list_get_iterator(session->opts.send_env);
                while (it != NULL) {
                    env_value = ssh_iterator_value(const char *, it);
                    cmp = strcmp(env_value, pattern);
                    next = it->next;
                    if (cmp == 0) {
                        free((void *)env_value);
                        ssh_list_remove(session->opts.send_env, it);
                    }
                    it = next;
                }
                rc = SSH_OK;
            } else {
                q = strdup(v);
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                /* Allocate on first use (no longer pre-allocated in ssh_new()) */
                if (session->opts.send_env == NULL) {
                    session->opts.send_env = ssh_list_new();
                    if (session->opts.send_env == NULL) {
                        free(q);
                        ssh_set_error_oom(session);
                        return -1;
                    }
                }
                rc = ssh_list_append(session->opts.send_env, q);
                if (rc < 0) {
                    free(q);
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_EXIT_ON_FORWARD_FAILURE:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                bool *x = (bool *)value;
                session->opts.exit_on_forward_failure = *x;
            }
            break;
        case SSH_OPTIONS_FORWARD_AGENT:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                bool *x = (bool *)value;
                session->opts.forward_agent = *x;
            }
            break;
        case SSH_OPTIONS_FORWARD_AGENT_SOCK_PATH:
            v = value;
            SAFE_FREE(session->opts.forward_agent_sock_path);
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                session->opts.forward_agent_sock_path =
                    ssh_path_expand_tilde(v);
                if (session->opts.forward_agent_sock_path == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        default:
            ssh_set_error(session, SSH_REQUEST_DENIED, "Unknown ssh option %d", type);
            return -1;
            break;
    }

    /*
     * The option was set successfully. Mark config-backed options as
     * explicitly set so that later processing of OpenSSH configuration files
     * keeps the application's value (issue #365). Options that map to
     * SOC_UNKNOWN are intentionally left unmarked.
     */
    opcode = ssh_opt_type_to_opcode(type);
    if (opcode != SOC_UNKNOWN) {
        session->opts.options_seen[opcode] = 1;
    }

    return 0;
}

/**
 * @brief This function returns the current algorithms used for algorithm
 * negotiation. It is either libssh default, option manually set or option
 * read from configuration file.
 *
 * This function will return NULL on error
 *
 * @param session An allocated SSH session structure.
 * @param algo One of the ssh_kex_types_e values.
 */
char *ssh_options_get_algo(ssh_session session,
                           enum ssh_kex_types_e algo)
{
    char *value = NULL;

    /* Check session and algo values are valid */

    if (session == NULL) {
        return NULL;
    }

    if (algo >= SSH_LANG_C_S) {
        ssh_set_error_invalid(session);
        return NULL;
    }

    /* Get the option the user has set, if there is one */
    value = session->opts.wanted_methods[algo];
    if (value == NULL) {
        /* The user has not set a value, return the appropriate default */
        if (ssh_fips_mode())
            value = (char *)ssh_kex_get_fips_methods(algo);
        else
            value = (char *)ssh_kex_get_default_methods(algo);
    }

    return value;
}


/**
 * @brief Get an integer or boolean SSH option from the session.
 *
 * This function is useful when the session options have been automatically
 * inferred from the environment or configuration files and the application
 * needs to read back an integer or boolean option value.
 *
 * @param  session   An allocated SSH session structure.
 *
 * @param  type     The option type to get. This could be one of the
 *                  following:
 *                  - SSH_OPTIONS_ADDRESS_FAMILY
 *                  - SSH_OPTIONS_BATCH_MODE
 *                  - SSH_OPTIONS_CONTROL_MASTER
 *                  - SSH_OPTIONS_PORT
 *                  - SSH_OPTIONS_IDENTITIES_ONLY
 *                  - SSH_OPTIONS_LOG_VERBOSITY
 *                  - SSH_OPTIONS_STRICTHOSTKEYCHECK
 *                  - SSH_OPTIONS_NODELAY
 *                  - SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS
 *                  - SSH_OPTIONS_ESCAPE_CHAR
 *                  - SSH_OPTIONS_SERVER_ALIVE_INTERVAL
 *                  - SSH_OPTIONS_SERVER_ALIVE_COUNT_MAX
 *                  - SSH_OPTIONS_FORWARD_AGENT
 *                  - SSH_OPTIONS_RSA_MIN_SIZE
 *                  - SSH_OPTIONS_PASSWORD_AUTH
 *                  - SSH_OPTIONS_PUBKEY_AUTH
 *                  - SSH_OPTIONS_KBDINT_AUTH
 *                  - SSH_OPTIONS_GSSAPI_AUTH
 *                  - SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS
 *                  - SSH_OPTIONS_GSSAPI_KEY_EXCHANGE
 *
 * @param  value    A pointer to an integer to store the option value.
 *
 * @return          SSH_OK on success, SSH_ERROR on error.
 */
int ssh_options_get_int(ssh_session session,
                        enum ssh_options_e type,
                        int *value)
{
    if (session == NULL || value == NULL) {
        return SSH_ERROR;
    }

    switch (type) {
    case SSH_OPTIONS_ADDRESS_FAMILY:
        *value = session->opts.address_family;
        break;
    case SSH_OPTIONS_PORT:
        *value = (session->opts.port == 0) ? 22 : (int)session->opts.port;
        break;
    case SSH_OPTIONS_BATCH_MODE:
        *value = session->opts.batch_mode ? 1 : 0;
        break;
    case SSH_OPTIONS_SERVER_ALIVE_INTERVAL:
        *value = session->opts.server_alive_interval;
        break;
    case SSH_OPTIONS_SERVER_ALIVE_COUNT_MAX:
        *value = session->opts.server_alive_count_max;
        break;
    case SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS:
        *value = session->opts.number_of_password_prompts;
        break;
    case SSH_OPTIONS_REQUEST_TTY:
        *value = session->opts.request_tty;
        break;
    case SSH_OPTIONS_ESCAPE_CHAR:
        *value = session->opts.escape_char;
        break;
    case SSH_OPTIONS_CONTROL_MASTER:
        *value = session->opts.control_master;
        break;
    case SSH_OPTIONS_IDENTITIES_ONLY:
        *value = session->opts.identities_only ? 1 : 0;
        break;
    case SSH_OPTIONS_LOG_VERBOSITY:
        *value = session->common.log_verbosity;
        break;
    case SSH_OPTIONS_STRICTHOSTKEYCHECK:
        *value = session->opts.StrictHostKeyChecking;
        break;
    case SSH_OPTIONS_NODELAY:
        *value = session->opts.nodelay;
        break;
    case SSH_OPTIONS_RSA_MIN_SIZE:
        *value = session->opts.rsa_min_size;
        break;
    case SSH_OPTIONS_PASSWORD_AUTH:
        *value = (session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH) ? 1 : 0;
        break;
    case SSH_OPTIONS_PUBKEY_AUTH:
        *value = (session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH) ? 1 : 0;
        break;
    case SSH_OPTIONS_KBDINT_AUTH:
        *value = (session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH) ? 1 : 0;
        break;
    case SSH_OPTIONS_GSSAPI_AUTH:
        *value = (session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH) ? 1 : 0;
        break;
    case SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS:
        *value = session->opts.gss_delegate_creds ? 1 : 0;
        break;
#ifdef WITH_GSSAPI
    case SSH_OPTIONS_GSSAPI_KEY_EXCHANGE:
        *value = session->opts.gssapi_key_exchange ? 1 : 0;
        break;
#endif
    case SSH_OPTIONS_EXIT_ON_FORWARD_FAILURE:
        *value = session->opts.exit_on_forward_failure ? 1 : 0;
        break;
    case SSH_OPTIONS_FORWARD_AGENT:
        *value = session->opts.forward_agent ? 1 : 0;
        break;
    default:
        ssh_set_error_invalid(session);
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @brief This function returns the port number set for the SSH session.
 *
 * It is either the port set explicitly via ssh_options_set() or the value
 * read from the configuration file. If no port has been set, the default
 * port 22 is returned.
 *
 * @param  session      An allocated SSH session structure.
 *
 * @param  port_target  A pointer to an unsigned integer to store the port.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_options_get_port(ssh_session session, unsigned int* port_target) {
    int value;
    int rc;

    rc = ssh_options_get_int(session, SSH_OPTIONS_PORT, &value);
    if (rc != SSH_OK) {
        return -1;
    }

    *port_target = (unsigned int)value;

    return 0;
}

/**
 * @brief This function can get ssh options, it does not support all options provided for
 *        ssh options set, but mostly those which a user-space program may care about having
 *        trusted the ssh driver to infer these values from underlying configuration files.
 *        It operates only on those SSH_OPTIONS_* which return char*. If you wish to receive
 *        the port then please use ssh_options_get_port() which returns an unsigned int.
 *
 * @param  session An allocated SSH session structure.
 *
 * @param  type The option type to get. This could be one of the
 *              following:
 *
 *              - SSH_OPTIONS_HOST:
 *                The hostname or ip address to connect to (const char *).
 *
 *              - SSH_OPTIONS_USER:
 *                The username for authentication (const char *).\n
 *                \n when not explicitly set this will be inferred from the
 *                ~/.ssh/config file.
 *
 *              - SSH_OPTIONS_IDENTITY:
 *                Get the first identity file name (const char *).\n
 *                \n
 *                By default `id_rsa`, `id_ecdsa`, `id_ed25519`, `id_ecdsa_sk`
 *                and `id_ed25519_sk` (when SK support is built in) files are
 *                used.
 *
 *              - SSH_OPTIONS_NEXT_IDENTITY:
 *                Get the next identity file name (const char *).\n
 *                \n
 *                Repeat calls to get all key paths. SSH_EOF is returned when
 *                the end of list is reached. Another call will start another
 *                iteration over the same list.
 *
 *              - SSH_OPTIONS_LOCAL_FORWARD:
 *                Get the first local forwarding specification from the
 *                local_forward list (const char *).\n
 *                \n
 *                Returns SSH_ERROR if the list is empty.
 *
 *              - SSH_OPTIONS_NEXT_LOCAL_FORWARD:
 *                Get the next local forwarding specification from the
 *                local_forward list (const char *).\n
 *                \n
 *                Repeat calls to get all entries. SSH_EOF is returned when
 *                the end of list is reached.
 *
 *              - SSH_OPTIONS_REMOTE_FORWARD:
 *                Get the first remote forwarding specification from the
 *                remote_forward list (const char *).\n
 *                \n
 *                Returns SSH_ERROR if the list is empty.
 *
 *              - SSH_OPTIONS_NEXT_REMOTE_FORWARD:
 *                Get the next remote forwarding specification from the
 *                remote_forward list (const char *).\n
 *                \n
 *                Repeat calls to get all entries. SSH_EOF is returned when
 *                the end of list is reached.
 *
 *              - SSH_OPTIONS_SEND_ENV:
 *                Get the first environment variable name pattern from the
 *                send_env list (const char *).\n
 *                \n
 *                Returns SSH_ERROR if the list is empty.
 *
 *              - SSH_OPTIONS_NEXT_SEND_ENV:
 *                Get the next environment variable name pattern from the
 *                send_env list (const char *).\n
 *                \n
 *                Repeat calls to get all patterns. SSH_EOF is returned when
 *                the end of list is reached.
 *
 *              - SSH_OPTIONS_FORWARD_AGENT_SOCK_PATH:
 *                Get the path to the local SSH agent socket used for agent
 *                forwarding.
 *
 *              - SSH_OPTIONS_PROXYCOMMAND:
 *                Get the proxycommand necessary to log into the
 *                remote host. When not explicitly set, it will be read
 *                from the ~/.ssh/config file.
 *
 *              - SSH_OPTIONS_GLOBAL_KNOWNHOSTS:
 *                Get the path to the global known_hosts file being used.
 *
 *              - SSH_OPTIONS_KNOWNHOSTS:
 *                Get the path to the known_hosts file being used.
 *
 *              - SSH_OPTIONS_CONTROL_PATH:
 *                Get the path to the control socket being used for connection
 *                multiplexing.
 *
 *              - SSH_OPTIONS_KEY_EXCHANGE:
 *                Get the key exchange methods to be used. If the option has
 *                not been set, returns the defaults.
 *
 *              - SSH_OPTIONS_HOSTKEYS:
 *                Get the preferred server host key types. If the option has
 *                not been set, returns the defaults.
 *
 *              - SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES:
 *                Get the preferred public key algorithms to be used for
 *                authentication.
 *
 *              - SSH_OPTIONS_CIPHERS_C_S:
 *                Get the symmetric cipher client to server. If the option has
 *                not been set, returns the defaults.
 *
 *              - SSH_OPTIONS_CIPHERS_S_C:
 *                Get the symmetric cipher server to client. If the option has
 *                not been set, returns the defaults.
 *
 *              - SSH_OPTIONS_HMAC_C_S:
 *                Get the Message Authentication Code algorithm client to server
 *                If the option has not been set, returns the defaults.
 *
 *              - SSH_OPTIONS_HMAC_S_C:
 *                Get the Message Authentication Code algorithm server to client
 *                If the option has not been set, returns the defaults.
 *
 *              - SSH_OPTIONS_COMPRESSION_C_S:
 *                Get the compression to use for client to server communication
 *                If the option has not been set, returns the defaults.
 *
 *              - SSH_OPTIONS_COMPRESSION_S_C:
 *                Get the compression to use for server to client communication
 *                If the option has not been set, returns the defaults.
 *
 * @param  value The value to get into. As a char**, space will be
 *               allocated by the function for the value, it is
 *               your responsibility to free the memory using
 *               ssh_string_free_char().
 *
 * @return       SSH_OK on success, SSH_ERROR on error.
 */
int ssh_options_get(ssh_session session, enum ssh_options_e type, char** value)
{
    char *src = NULL;

    if (session == NULL) {
        return SSH_ERROR;
    }

    if (value == NULL) {
        ssh_set_error_invalid(session);
        return SSH_ERROR;
    }

    switch(type)
    {
        case SSH_OPTIONS_HOST:
            src = session->opts.host ? session->opts.host
                                     : session->opts.originalhost;
            break;

        case SSH_OPTIONS_USER:
            src = session->opts.username;
            break;

        case SSH_OPTIONS_PREFERRED_AUTHENTICATIONS:
            src = session->opts.preferred_authentications;
            break;

        case SSH_OPTIONS_IDENTITY: {
            struct ssh_iterator *it = NULL;
            it = ssh_list_get_iterator(session->opts.identity);
            if (it == NULL) {
                it = ssh_list_get_iterator(session->opts.identity_non_exp);
            }
            if (it == NULL) {
                return SSH_ERROR;
            }
            src = ssh_iterator_value(char *, it);
            break;
        }

        case SSH_OPTIONS_NEXT_IDENTITY: {
            if (session->opts.identity_it != NULL) {
                /* Move to the next item */
                session->opts.identity_it = session->opts.identity_it->next;
                if (session->opts.identity_it == NULL) {
                    *value = NULL;
                    return SSH_EOF;
                }
            } else {
                /* Get iterator from opts */
                struct ssh_iterator *it = NULL;
                it = ssh_list_get_iterator(session->opts.identity);
                if (it == NULL) {
                    it = ssh_list_get_iterator(session->opts.identity_non_exp);
                }
                if (it == NULL) {
                    return SSH_ERROR;
                }
                session->opts.identity_it = it;
            }
            src = ssh_iterator_value(char *, session->opts.identity_it);
            break;
        }

        case SSH_OPTIONS_LOCAL_FORWARD: {
            struct ssh_iterator *it = NULL;
            it = ssh_list_get_iterator(session->opts.local_forward);
            if (it == NULL) {
                return SSH_ERROR;
            }
            session->opts.local_forward_it = it;
            src = ssh_iterator_value(char *, it);
            break;
        }

        case SSH_OPTIONS_NEXT_LOCAL_FORWARD:
            if (session->opts.local_forward_it != NULL) {
                session->opts.local_forward_it =
                    session->opts.local_forward_it->next;
                if (session->opts.local_forward_it == NULL) {
                    *value = NULL;
                    return SSH_EOF;
                }
            } else {
                return SSH_ERROR;
            }
            src = ssh_iterator_value(char *, session->opts.local_forward_it);
            break;

        case SSH_OPTIONS_REMOTE_FORWARD: {
            struct ssh_iterator *it = NULL;
            it = ssh_list_get_iterator(session->opts.remote_forward);
            if (it == NULL) {
                return SSH_ERROR;
            }
            session->opts.remote_forward_it = it;
            src = ssh_iterator_value(char *, it);
            break;
        }

        case SSH_OPTIONS_NEXT_REMOTE_FORWARD:
            if (session->opts.remote_forward_it != NULL) {
                session->opts.remote_forward_it =
                    session->opts.remote_forward_it->next;
                if (session->opts.remote_forward_it == NULL) {
                    *value = NULL;
                    return SSH_EOF;
                }
            } else {
                return SSH_ERROR;
            }
            src = ssh_iterator_value(char *, session->opts.remote_forward_it);
            break;

        case SSH_OPTIONS_SEND_ENV: {
            struct ssh_iterator *it = NULL;
            it = ssh_list_get_iterator(session->opts.send_env);
            if (it == NULL) {
                return SSH_ERROR;
            }
            session->opts.send_env_it = it;
            src = ssh_iterator_value(char *, it);
            break;
        }

        case SSH_OPTIONS_NEXT_SEND_ENV:
            if (session->opts.send_env_it != NULL) {
                session->opts.send_env_it = session->opts.send_env_it->next;
                if (session->opts.send_env_it == NULL) {
                    *value = NULL;
                    return SSH_EOF;
                }
            } else {
                return SSH_ERROR;
            }
            src = ssh_iterator_value(char *, session->opts.send_env_it);
            break;

        case SSH_OPTIONS_PROXYCOMMAND:
            src = session->opts.ProxyCommand;
            break;

        case SSH_OPTIONS_KNOWNHOSTS:
            src = session->opts.knownhosts;
            break;

        case SSH_OPTIONS_GLOBAL_KNOWNHOSTS:
            src = session->opts.global_knownhosts;
            break;
        case SSH_OPTIONS_CONTROL_PATH:
            src = session->opts.control_path;
            break;

        case SSH_OPTIONS_FORWARD_AGENT_SOCK_PATH:
            src = session->opts.forward_agent_sock_path;
            break;

        case SSH_OPTIONS_CIPHERS_C_S:
            src = ssh_options_get_algo(session, SSH_CRYPT_C_S);
            break;

        case SSH_OPTIONS_CIPHERS_S_C:
            src = ssh_options_get_algo(session, SSH_CRYPT_S_C);
            break;

        case SSH_OPTIONS_KEY_EXCHANGE:
            src = ssh_options_get_algo(session, SSH_KEX);
            break;

        case SSH_OPTIONS_HOSTKEYS:
            src = ssh_options_get_algo(session, SSH_HOSTKEYS);
            break;

        case SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES:
            src = session->opts.pubkey_accepted_types;
            break;

        case SSH_OPTIONS_HMAC_C_S:
            src = ssh_options_get_algo(session, SSH_MAC_C_S);
            break;

        case SSH_OPTIONS_HMAC_S_C:
            src = ssh_options_get_algo(session, SSH_MAC_S_C);
            break;

        case SSH_OPTIONS_COMPRESSION_C_S:
            src = ssh_options_get_algo(session, SSH_COMP_C_S);
            break;

        case SSH_OPTIONS_COMPRESSION_S_C:
            src = ssh_options_get_algo(session, SSH_COMP_S_C);
            break;

        default:
            ssh_set_error(session, SSH_REQUEST_DENIED, "Unknown ssh option %d", type);
            return SSH_ERROR;
        break;
    }
    if (src == NULL) {
        return SSH_ERROR;
    }
    *value = strdup(src);
    if (*value == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    return SSH_OK;
}

/**
 * @brief Parse command line arguments.
 *
 * This is a helper for your application to generate the appropriate
 * options from the command line arguments.\n
 * The argv array and argc value are changed so that the parsed
 * arguments won't appear anymore in them.\n
 * The single arguments (without switches) are not parsed. thus,
 * myssh -l user localhost\n
 * The command won't set the hostname value of options to localhost.
 *
 * @param session       The session to configure.
 *
 * @param argcptr       The pointer to the argument count.
 *
 * @param argv          The arguments list pointer.
 *
 * @returns 0 on success, < 0 on error.
 *
 * @see ssh_session_new()
 */
int ssh_options_getopt(ssh_session session, int *argcptr, char **argv)
{
    char *user = NULL;
    char *cipher = NULL;
    char *identity = NULL;
    char *port = NULL;
    char **save = NULL;
    char **tmp = NULL;
    size_t i = 0;
    int argc = *argcptr;
    int compress = 0;
    size_t current = 0;
    int opt_rc = 0;
    int saveoptind = optind; /* need to save 'em */
    int saveopterr = opterr;
    int opt;
    int rv;

    /* Keep preconfigured global log level and let -v flags raise it further. */
    int verbosity = ssh_get_log_level();
    int verbosity_set = 0;
    if (argc <= 1) {
        return SSH_OK;
    }

    opterr = 0; /* shut up getopt */
    while ((opt = getopt(argc, argv, "c:i:o:Cl:p:qvb:r12")) != -1) {
        switch(opt) {
        case 'l':
            user = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 'v':
            verbosity++;
            verbosity_set = 1;
            break;
        case 'q':
            verbosity = SSH_LOG_NOLOG;
            verbosity_set = 1;
            break;
        case 'r':
            break;
        case 'c':
            cipher = optarg;
            break;
        case 'i':
            identity = optarg;
            break;
        case 'C':
            compress++;
            break;
        case 'o':
            opt_rc = ssh_config_parse_line_cli(session, optarg);
            break;
        case '2':
        case '1':
            break;
        default:
            {
                tmp = realloc(save, (current + 1) * sizeof(char*));
                if (tmp == NULL) {
                    SAFE_FREE(save);
                    ssh_set_error_oom(session);
                    return -1;
                }
                save = tmp;
                save[current] = argv[optind-1];
                current++;
                /* We can not use optarg here as getopt does not set it for
                 * unknown options. We need to manually extract following
                 * option and skip it manually from further processing */
                if (optind < argc && argv[optind][0] != '-') {
                    tmp = realloc(save, (current + 1) * sizeof(char*));
                    if (tmp == NULL) {
                        SAFE_FREE(save);
                        ssh_set_error_oom(session);
                        return -1;
                    }
                    save = tmp;
                    save[current++] = argv[optind];
                    optind++;
                }
            }
        } /* switch */
        if (opt_rc == SSH_ERROR) {
            break;
        }
    } /* while */
    opterr = saveopterr;
    tmp = realloc(save, (current + (argc - optind)) * sizeof(char*));
    if (tmp == NULL) {
        SAFE_FREE(save);
        ssh_set_error_oom(session);
        return -1;
    }
    save = tmp;
    while (optind < argc) {
        tmp = realloc(save, (current + 1) * sizeof(char*));
        if (tmp == NULL) {
            SAFE_FREE(save);
            ssh_set_error_oom(session);
            return -1;
        }
        save = tmp;
        save[current] = argv[optind];
        current++;
        optind++;
    }

    optind = saveoptind;

    if (opt_rc == SSH_ERROR) {
        SAFE_FREE(save);
        return SSH_ERROR;
    }

    /* first recopy the save vector into the original's */
    for (i = 0; i < current; i++) {
        /* don't erase argv[0] */
        argv[ i + 1] = save[i];
    }
    argv[current + 1] = NULL;
    *argcptr = current + 1;
    SAFE_FREE(save);

    if (verbosity_set) {
        verbosity = MIN(verbosity, SSH_LOG_FUNCTIONS);
        rv = ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
        if (rv < 0) {
            return SSH_ERROR;
        }
    }

    if (compress) {
        if (ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes") < 0) {
            return SSH_ERROR;
        }
    }

    if (cipher) {
        int rc_c_s = ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, cipher);
        int rc_s_c = ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, cipher);
        if (rc_c_s < 0 || rc_s_c < 0) {
            return SSH_ERROR;
        }
    }

    if (user) {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
            return SSH_ERROR;
        }
    }

    if (identity) {
        if (ssh_options_set(session, SSH_OPTIONS_IDENTITY, identity) < 0) {
            return SSH_ERROR;
        }
    }

    if (port != NULL) {
        ssh_options_set(session, SSH_OPTIONS_PORT_STR, port);
    }

    return SSH_OK;
}

/**
 * @brief Parse the ssh config file.
 *
 * This should be the last call of all options. Options that were already set
 * explicitly via ssh_options_set() take precedence and are not overwritten by
 * the configuration file, matching OpenSSH's "first obtained value wins"
 * behavior. Accumulative options such as IdentityFile and CertificateFile, as
 * well as host-alias resolution via HostName, are still applied from the
 * configuration. It requires that the host name is already set with
 * ssh_options_set(SSH_OPTIONS_HOST).
 *
 * @param  session      SSH session handle
 *
 * @param  filename     The options file to use, if NULL the default
 *                      ~/.ssh/config and /etc/ssh/ssh_config will be used.
 *                      If complied with support for hermetic-usr,
 *                      /usr/etc/ssh/ssh_config will be used last.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see ssh_options_set()
 */
int ssh_options_parse_config(ssh_session session, const char *filename)
{
    char *expanded_filename = NULL;
    int r;
    FILE *fp = NULL;

    if (session == NULL) {
        return -1;
    }
    if (session->opts.originalhost == NULL) {
        ssh_set_error_invalid(session);
        return -1;
    }

    if (session->opts.sshdir == NULL) {
        r = ssh_options_set(session, SSH_OPTIONS_SSH_DIR, NULL);
        if (r < 0) {
            ssh_set_error_oom(session);
            return -1;
        }
    }

    /* set default filename */
    if (filename == NULL) {
        expanded_filename = ssh_path_expand_escape(session, "%d/.ssh/config");
    } else {
        expanded_filename = ssh_path_expand_escape(session, filename);
    }
    if (expanded_filename == NULL) {
        return -1;
    }

    r = ssh_config_parse_file(session, expanded_filename);
    if (r < 0) {
        goto out;
    }
    if (filename == NULL) {
        fp = ssh_strict_fopen(GLOBAL_CLIENT_CONFIG, SSH_MAX_CONFIG_FILE_SIZE);
        if (fp != NULL) {
            filename = GLOBAL_CLIENT_CONFIG;
#ifdef USR_GLOBAL_CLIENT_CONFIG
        } else {
            fp = ssh_strict_fopen(USR_GLOBAL_CLIENT_CONFIG,
                                  SSH_MAX_CONFIG_FILE_SIZE);
            if (fp != NULL) {
                filename = USR_GLOBAL_CLIENT_CONFIG;
            }
#endif
        }

        if (fp) {
            SSH_LOG(SSH_LOG_PACKET,
                    "Reading configuration data from %s",
                    filename);
            r = ssh_config_parse(session, fp, true);
            fclose(fp);
        }
    }

    /* Do not process the default configuration as part of connection again */
    session->opts.config_processed = true;
out:
    free(expanded_filename);
    return r;
}

/**
 * @internal
 *
 * @brief Checks if a hostname requires lowercasing.
 *
 * This function determines if the given host string is a standard hostname
 * that should be converted to lowercase for case-insensitive matching.
 * It returns false for IPv4/IPv6 addresses or strings containing formatting
 * tokens (e.g., '%'), as these should remain unmodified.
 *
 * @param[in]  host  The hostname string to evaluate.
 *
 * @return     true if the host should be lowercased, false otherwise.
 */
static bool ssh_host_requires_lowercase(const char *host) {
    if (strchr(host, '%') != NULL || strchr(host, ':') != NULL ||
        strspn(host, "0123456789.") == strlen(host)) {
        return false;
    }
    return !ssh_is_ipaddr(host);
}

/**
 * @internal
 *
 * @brief Apply session options defaults and resolve some configuration paths.
 *
 * @param[in] session  The SSH session to apply defaults to.
 *
 * @return  `SSH_OK` on success, `SSH_ERROR` on error.
 */
int ssh_options_apply(ssh_session session)
{
    char *tmp = NULL;
    int rc;

    if (session->opts.host != NULL) {
        char *normalized_host = NULL;
        rc = ssh_normalize_loose_ip(session->opts.host, &normalized_host);
        if (rc == -1) {
            /* Error (e.g. NULL input or OOM) — leave host as it is */
        } else if (rc == 0) {
            /* Was a loose IP — use the normalized dotted-quad form */
            SAFE_FREE(session->opts.host);
            session->opts.host = normalized_host;
        } else {
            /* rc == 1: not a loose IP — lowercase if it's not a strict IP */
            bool requires_lowercase = ssh_host_requires_lowercase(session->opts.host);
            if (requires_lowercase) {
                char *lower = ssh_lowercase(session->opts.host);
                if (lower != NULL) {
                    SAFE_FREE(session->opts.host);
                    session->opts.host = lower;
                }
            }
        }
    }

    if (session->opts.sshdir == NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_SSH_DIR, NULL);
        if (rc < 0) {
            return -1;
        }
    }

    if (session->opts.username == NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_USER, NULL);
        if (rc < 0) {
            return -1;
        }
    }

    if (session->opts.config_hostname != NULL) {
        char *saved_host = NULL;

        tmp = ssh_path_expand_hostname(session, session->opts.config_hostname);
        if (tmp == NULL) {
            return -1;
        }
        if (session->opts.host != NULL) {
            saved_host = strdup(session->opts.host);
            if (saved_host == NULL) {
                free(tmp);
                ssh_set_error_oom(session);
                return -1;
            }
        }
        session->opts.config_hostname_only = true;
        rc = ssh_options_set(session, SSH_OPTIONS_HOST, tmp);
        session->opts.config_hostname_only = false;
        if (rc != SSH_OK) {
            /* If HostName expansion leaves a literal '%', keep the current
             * host instead of treating the deferred HostName as fatal.
             */
            if (strchr(tmp, '%') == NULL) {
                SAFE_FREE(saved_host);
                free(tmp);
                return -1;
            }
            SSH_LOG(SSH_LOG_WARN,
                    "HostName %s contains unknown expansion tokens and could "
                    "not be applied; falling back to current host",
                    tmp);
            SAFE_FREE(session->opts.host);
            session->opts.host = saved_host;
            saved_host = NULL;
        }
        SAFE_FREE(saved_host);
        free(tmp);
        SAFE_FREE(session->opts.config_hostname);
    }

    /* Expand percent tokens in the username at apply time, matching OpenSSH
     * which defers User expansion to after all options are resolved.
     */
    if ((session->opts.exp_flags & SSH_OPT_EXP_FLAG_USERNAME) == 0 &&
        session->opts.username != NULL) {
        tmp = ssh_path_expand_escape(session, session->opts.username);
        if (tmp != NULL) {
            free(session->opts.username);
            session->opts.username = tmp;
            tmp = NULL;
        }
        /* On failure, keep the raw string — best-effort expansion */
        session->opts.exp_flags |= SSH_OPT_EXP_FLAG_USERNAME;
    }

    if ((session->opts.exp_flags & SSH_OPT_EXP_FLAG_KNOWNHOSTS) == 0) {
        if (session->opts.knownhosts == NULL) {
            tmp = ssh_path_expand_escape(session, "%d/.ssh/known_hosts");
        } else {
            tmp = ssh_path_expand_escape(session, session->opts.knownhosts);
        }
        if (tmp == NULL) {
            return -1;
        }
        free(session->opts.knownhosts);
        session->opts.knownhosts = tmp;
        session->opts.exp_flags |= SSH_OPT_EXP_FLAG_KNOWNHOSTS;
    }

    if ((session->opts.exp_flags & SSH_OPT_EXP_FLAG_GLOBAL_KNOWNHOSTS) == 0) {
        if (session->opts.global_knownhosts == NULL) {
            tmp = strdup(GLOBAL_CONF_DIR "/ssh_known_hosts");
        } else {
            tmp = ssh_path_expand_escape(session,
                                         session->opts.global_knownhosts);
        }
        if (tmp == NULL) {
            return -1;
        }
        free(session->opts.global_knownhosts);
        session->opts.global_knownhosts = tmp;
        session->opts.exp_flags |= SSH_OPT_EXP_FLAG_GLOBAL_KNOWNHOSTS;
    }


    if ((session->opts.exp_flags & SSH_OPT_EXP_FLAG_PROXYCOMMAND) == 0) {
        if (session->opts.ProxyCommand != NULL) {
            char *p = NULL;
            size_t plen = strlen(session->opts.ProxyCommand) +
                          5 /* strlen("exec ") */;

            if (strncmp(session->opts.ProxyCommand, "exec ", 5) != 0) {
                p = malloc(plen + 1 /* \0 */);
                if (p == NULL) {
                    return -1;
                }

                rc = snprintf(p, plen + 1, "exec %s", session->opts.ProxyCommand);
                if ((size_t)rc != plen) {
                    free(p);
                    return -1;
                }
                tmp = ssh_path_expand_escape(session, p);
                free(p);
            } else {
                tmp = ssh_path_expand_escape(session,
                                             session->opts.ProxyCommand);
            }

            if (tmp == NULL) {
                return -1;
            }
            free(session->opts.ProxyCommand);
            session->opts.ProxyCommand = tmp;
            session->opts.exp_flags |= SSH_OPT_EXP_FLAG_PROXYCOMMAND;
        }
    }

    if ((session->opts.exp_flags & SSH_OPT_EXP_FLAG_CONTROL_PATH) == 0) {
        if (session->opts.control_path != NULL) {
            tmp = ssh_path_expand_escape(session, session->opts.control_path);
            if (tmp == NULL) {
                return -1;
            }
            free(session->opts.control_path);
            session->opts.control_path = tmp;
            session->opts.exp_flags |= SSH_OPT_EXP_FLAG_CONTROL_PATH;
        }
    }

    /* Allocate on first use (no longer pre-allocated in ssh_new()) */
    if (session->opts.identity == NULL) {
        session->opts.identity = ssh_list_new();
        if (session->opts.identity == NULL) {
            return -1;
        }
    }

    for (tmp = ssh_list_pop_head(char *, session->opts.identity_non_exp);
         tmp != NULL;
         tmp = ssh_list_pop_head(char *, session->opts.identity_non_exp)) {
        char *id = tmp;
        if (strncmp(id, "pkcs11:", 6) != 0) {
            /* PKCS#11 URIs are using percent-encoding so we can not mix
             * it with ssh expansion of ssh escape characters.
             */
            tmp = ssh_path_expand_escape(session, id);
            free(id);
            if (tmp == NULL) {
                return -1;
            }
        }

        /* use append to keep the order at first call and use prepend
         * to put anything that comes on the nth calls to the beginning */
        if (session->opts.exp_flags & SSH_OPT_EXP_FLAG_IDENTITY) {
            rc = ssh_list_prepend(session->opts.identity, tmp);
        } else {
            rc = ssh_list_append(session->opts.identity, tmp);
        }
        if (rc != SSH_OK) {
            free(tmp);
            return -1;
        }
    }
    session->opts.exp_flags |= SSH_OPT_EXP_FLAG_IDENTITY;

    /* Allocate on first use (no longer pre-allocated in ssh_new()) */
    if (session->opts.certificate == NULL) {
        session->opts.certificate = ssh_list_new();
        if (session->opts.certificate == NULL) {
            return -1;
        }
    }

    for (tmp = ssh_list_pop_head(char *, session->opts.certificate_non_exp);
         tmp != NULL;
         tmp = ssh_list_pop_head(char *, session->opts.certificate_non_exp)) {
        char *id = tmp;

        tmp = ssh_path_expand_escape(session, id);
        free(id);
        if (tmp == NULL) {
            return -1;
        }

        rc = ssh_list_append(session->opts.certificate, tmp);
        if (rc != SSH_OK) {
            free(tmp);
            return -1;
        }
    }

#ifdef WITH_GSSAPI
    if (session->opts.gssapi_key_exchange) {
        rc = ssh_gssapi_check_client_config(session);
        if (rc != SSH_OK) {
            SSH_LOG(SSH_LOG_WARN, "Disabled GSSAPI key exchange");
            session->opts.gssapi_key_exchange = false;
        }
    }
#endif

    return 0;
}

/** @} */

#ifdef WITH_SERVER
static bool ssh_bind_key_size_allowed(ssh_bind sshbind, ssh_key key)
{
    int min_size = 0;

    switch (ssh_key_type(key)) {
    case SSH_KEYTYPE_RSA:
    case SSH_KEYTYPE_RSA_CERT01:
        min_size = sshbind->rsa_min_size;
        return ssh_key_size_allowed_rsa(min_size, key);
    default:
        return true;
    }
}

/**
 * @addtogroup libssh_server
 * @{
 */
static int
ssh_bind_set_key(ssh_bind sshbind, char **key_loc, const void *value)
{
    if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
    } else {
        SAFE_FREE(*key_loc);
        *key_loc = strdup(value);
        if (*key_loc == NULL) {
            ssh_set_error_oom(sshbind);
            return -1;
        }
    }
    return 0;
}

static int ssh_bind_set_algo(ssh_bind sshbind,
                             enum ssh_kex_types_e algo,
                             const char *list,
                             char **place)
{
    /* sshbind is needed only for ssh_set_error which takes void*
     * the typecast is only to satisfy function parameter type */
    return ssh_options_set_algo((ssh_session)sshbind, algo, list, place);
}

/**
 * @brief Set options for an SSH server bind.
 *
 * @param  sshbind      The ssh server bind to configure.
 *
 * @param  type         The option type to set. This should be one of the
 *                      following:
 *
 *                      - SSH_BIND_OPTIONS_HOSTKEY:
 *                        Set the path to an ssh host key, regardless
 *                        of type.  Only one key from per key type
 *                        (RSA, ED25519 and ECDSA) is allowed in an ssh_bind
 *                        at a time, and later calls to this function
 *                        with this option for the same key type will
 *                        override prior calls (const char *).
 *
 *                      - SSH_BIND_OPTIONS_BINDADDR:
 *                        Set the IP address to bind (const char *).
 *
 *                      - SSH_BIND_OPTIONS_BINDPORT:
 *                        Set the port to bind (unsigned int).
 *
 *                      - SSH_BIND_OPTIONS_BINDPORT_STR:
 *                        Set the port to bind (const char *).
 *
 *                      - SSH_BIND_OPTIONS_LOG_VERBOSITY:
 *                        Set the session logging verbosity (int).
 *                        The logging verbosity should have one of the
 *                        following values, which are listed in order
 *                        of increasing verbosity.  Every log message
 *                        with verbosity less than or equal to the
 *                        logging verbosity will be shown.
 *                        - SSH_LOG_NOLOG: No logging
 *                        - SSH_LOG_WARNING: Only warnings
 *                        - SSH_LOG_PROTOCOL: High level protocol information
 *                        - SSH_LOG_PACKET: Lower level protocol information,
 *                          packet level
 *                        - SSH_LOG_FUNCTIONS: Every function path
 *                        The default is SSH_LOG_NOLOG.
 *
 *                      - SSH_BIND_OPTIONS_LOG_VERBOSITY_STR:
 *                        Set the session logging verbosity via a
 *                        string that will be converted to a numerical
 *                        value (e.g. "3") and interpreted according
 *                        to the values of
 *                        SSH_BIND_OPTIONS_LOG_VERBOSITY above
 *                        (const char *).
 *
 *                      - SSH_BIND_OPTIONS_RSAKEY:
 *                        Deprecated alias to SSH_BIND_OPTIONS_HOSTKEY
 *                        (const char *).
 *
 *                      - SSH_BIND_OPTIONS_ECDSAKEY:
 *                        Deprecated alias to SSH_BIND_OPTIONS_HOSTKEY
 *                        (const char *).
 *
 *                      - SSH_BIND_OPTIONS_BANNER:
 *                        Set the server banner sent to clients (const char *).
 *
 *                      - SSH_BIND_OPTIONS_DSAKEY:
 *                        This is DEPRECATED, please do not use.
 *
 *                      - SSH_BIND_OPTIONS_IMPORT_KEY:
 *                        Set the Private Key for the server directly
 *                        (ssh_key). It will be free'd by ssh_bind_free().
 *
 *                      - SSH_BIND_OPTIONS_IMPORT_KEY_STR:
 *                        Set the Private key for the server from a
 *                        base64 encoded buffer (const char *).
 *
 *                      - SSH_BIND_OPTIONS_CIPHERS_C_S:
 *                        Set the symmetric cipher client to server
 *                        (const char *, comma-separated list).
 *
 *                      - SSH_BIND_OPTIONS_CIPHERS_S_C:
 *                        Set the symmetric cipher server to client
 *                        (const char *, comma-separated list).
 *
 *                      - SSH_BIND_OPTIONS_KEY_EXCHANGE:
 *                        Set the key exchange method to be used
 *                        (const char *, comma-separated list). ex:
 *                        "ecdh-sha2-nistp256,diffie-hellman-group14-sha1"
 *
 *                      - SSH_BIND_OPTIONS_HMAC_C_S:
 *                        Set the Message Authentication Code algorithm client
 *                        to server (const char *, comma-separated list).
 *
 *                      - SSH_BIND_OPTIONS_HMAC_S_C:
 *                        Set the Message Authentication Code algorithm server
 *                        to client (const char *, comma-separated list).
 *
 *                      - SSH_BIND_OPTIONS_CONFIG_DIR:
 *                        Set the directory (const char *, format string)
 *                        to be used when the "%d" scape is used when providing
 *                        paths of configuration files to
 *                        ssh_bind_options_parse_config().
 *
 *                      - SSH_BIND_OPTIONS_PROCESS_CONFIG
 *                        Set it to false to disable automatic processing of
 *                        system-wide configuration files. LibSSH automatically
 *                        uses these configuration files otherwise. This
 *                        option will only have effect if set before any call
 *                        to ssh_bind_options_parse_config() (bool).
 *
 *                      - SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES:
 *                        Set the public key algorithm accepted by the server
 *                        (const char *, comma-separated list).
 *
 *                      - SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS:
 *                        Set the list of allowed hostkey signatures algorithms
 *                        to offer to the client, ordered by preference. This
 *                        list is used as a filter when creating the list of
 *                        algorithms to offer to the client: first the list of
 *                        possible algorithms is created from the list of keys
 *                        set and then filtered against this list.
 *                        (const char *, comma-separated list).
 *
 *                      - SSH_BIND_OPTIONS_MODULI
 *                        Set the path to the moduli file. Defaults to
 *                        /etc/ssh/moduli if not specified (const char *).
 *
 *                      - SSH_BIND_OPTIONS_RSA_MIN_SIZE
 *                        Set the minimum RSA key size in bits to be accepted by
 *                        the server for both authentication and hostkey
 *                        operations. The values under 1024 bits are not accepted
 *                        even with this configuration option as they are
 *                        considered completely broken. Setting 0 will revert
 *                        the value to defaults.
 *                        Default is 3072 bits or 2048 bits in FIPS mode.
 *                        (int)
 *
 *                      - SSH_BIND_OPTIONS_GSSAPI_KEY_EXCHANGE
 *                        Set true to enable GSSAPI key exchange,
 *                        false to disable GSSAPI key exchange. (bool)
 *
 *                      - SSH_BIND_OPTIONS_GSSAPI_KEY_EXCHANGE_ALGS
 *                        Set the GSSAPI key exchange method to be used
 *                        (const char *, comma-separated list).
 *                        ex: "gss-group14-sha256-,gss-group16-sha512-"
 *
 * @param  value        The value to set. This is a generic pointer and the
 *                      datatype which should be used is described at the
 *                      corresponding value of type above.
 *
 * @return              0 on success, < 0 on error, invalid option, or
 *                      parameter.
 *
 * @warning             When the option value to set is represented via a
 *                      pointer (e.g const char * in case of strings, ssh_key
 *                      in case of a libssh key), the value parameter should be
 *                      that pointer. Do NOT pass a pointer to a pointer (const
 *                      char **, ssh_key *)
 *
 * @warning             When the option value to set is not a pointer (e.g int,
 *                      unsigned int, bool, long), the value parameter should be
 *                      a pointer to the location storing the value to set (int
 *                      *, unsigned int *, bool *, long *)
 *
 * @warning             If the value parameter has an invalid type (e.g if its
 *                      not a pointer when it should have been a pointer, or if
 *                      its a pointer to a pointer when it should have just been
 *                      a pointer), then the behaviour is undefined.
 *
 * @warning             Options set via this function may be overridden if a
 *                      configuration file is parsed afterwards (e.g., by an
 *                      implicit call to ssh_bind_options_parse_config() inside
 *                      ssh_bind_listen(), or by a manual call to the same
 *                      function) and contains the same options.\n
 *                      It is the caller’s responsibility to ensure the correct
 *                      order of API calls if explicit options must take
 *                      precedence.
 */
int
ssh_bind_options_set(ssh_bind sshbind,
                     enum ssh_bind_options_e type,
                     const void *value)
{
    bool allowed;
    char *p = NULL, *q = NULL;
    const char *v = NULL;
    int i, rc;
    char **wanted_methods = sshbind->wanted_methods;

    if (sshbind == NULL) {
        return -1;
    }

    switch (type) {
    case SSH_BIND_OPTIONS_RSAKEY:
    case SSH_BIND_OPTIONS_ECDSAKEY:
        /* deprecated */
    case SSH_BIND_OPTIONS_HOSTKEY:
    case SSH_BIND_OPTIONS_IMPORT_KEY:
    case SSH_BIND_OPTIONS_IMPORT_KEY_STR:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            int key_type;
            ssh_key *bind_key_loc = NULL;
            ssh_key key = NULL;
            char **bind_key_path_loc = NULL;

            if (type == SSH_BIND_OPTIONS_IMPORT_KEY_STR) {
                const char *key_str = (const char *)value;
                rc = ssh_pki_import_privkey_base64(key_str,
                                                   NULL,
                                                   NULL,
                                                   NULL,
                                                   &key);
                if (rc == SSH_ERROR) {
                    ssh_set_error(sshbind,
                                  SSH_FATAL,
                                  "Failed to import key from buffer");
                    return -1;
                }
            } else if (type == SSH_BIND_OPTIONS_IMPORT_KEY) {
                key = (ssh_key)value;
            } else {
                rc = ssh_pki_import_privkey_file(value, NULL, NULL, NULL, &key);
                if (rc != SSH_OK) {
                    return -1;
                }
            }
            allowed = ssh_bind_key_size_allowed(sshbind, key);
            if (!allowed) {
                ssh_set_error(sshbind,
                              SSH_FATAL,
                              "The host key size %d is too small.",
                              ssh_key_size(key));
                if (type != SSH_BIND_OPTIONS_IMPORT_KEY) {
                    SSH_KEY_FREE(key);
                }
                return -1;
            }
            key_type = ssh_key_type(key);
            switch (key_type) {
            case SSH_KEYTYPE_ECDSA_P256:
            case SSH_KEYTYPE_ECDSA_P384:
            case SSH_KEYTYPE_ECDSA_P521:
#ifdef HAVE_ECC
                bind_key_loc = &sshbind->ecdsa;
                bind_key_path_loc = &sshbind->ecdsakey;
#else
                ssh_set_error(sshbind,
                              SSH_FATAL,
                              "ECDSA key used and libssh compiled "
                              "without ECDSA support");
#endif
                break;
            case SSH_KEYTYPE_RSA:
                bind_key_loc = &sshbind->rsa;
                bind_key_path_loc = &sshbind->rsakey;
                break;
            case SSH_KEYTYPE_ED25519:
                bind_key_loc = &sshbind->ed25519;
                bind_key_path_loc = &sshbind->ed25519key;
                break;
            default:
                ssh_set_error(sshbind,
                              SSH_FATAL,
                              "Unsupported key type %d",
                              key_type);
            }
            if (type == SSH_BIND_OPTIONS_RSAKEY ||
                type == SSH_BIND_OPTIONS_ECDSAKEY ||
                type == SSH_BIND_OPTIONS_HOSTKEY) {
                if (bind_key_loc == NULL) {
                    ssh_key_free(key);
                    return -1;
                }
                /* Set the location of the key on disk even though we don't
                   need it in case some other function wants it */
                rc = ssh_bind_set_key(sshbind, bind_key_path_loc, value);
                if (rc < 0) {
                    ssh_key_free(key);
                    return -1;
                }
            } else if (type == SSH_BIND_OPTIONS_IMPORT_KEY_STR) {
                if (bind_key_loc == NULL) {
                    ssh_key_free(key);
                    return -1;
                }
            } else {
                if (bind_key_loc == NULL) {
                    return -1;
                }
            }
            ssh_key_free(*bind_key_loc);
            *bind_key_loc = key;
        }
        break;
    case SSH_BIND_OPTIONS_BINDADDR:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            SAFE_FREE(sshbind->bindaddr);
            sshbind->bindaddr = strdup(value);
            if (sshbind->bindaddr == NULL) {
                ssh_set_error_oom(sshbind);
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_BINDPORT:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            int *x = (int *)value;
            sshbind->bindport = *x & 0xffffU;
        }
        break;
    case SSH_BIND_OPTIONS_BINDPORT_STR:
        if (value == NULL) {
            sshbind->bindport = 22 & 0xffffU;
        } else {
            q = strdup(value);
            if (q == NULL) {
                ssh_set_error_oom(sshbind);
                return -1;
            }
            i = strtol(q, &p, 10);
            if (q == p) {
                SSH_LOG(SSH_LOG_DEBUG, "No bind port was parsed");
                SAFE_FREE(q);
                return -1;
            }
            SAFE_FREE(q);

            sshbind->bindport = i & 0xffffU;
        }
        break;
    case SSH_BIND_OPTIONS_LOG_VERBOSITY:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            int *x = (int *)value;
            ssh_set_log_level(*x & 0xffffU);
        }
        break;
    case SSH_BIND_OPTIONS_LOG_VERBOSITY_STR:
        if (value == NULL) {
            ssh_set_log_level(0);
        } else {
            q = strdup(value);
            if (q == NULL) {
                ssh_set_error_oom(sshbind);
                return -1;
            }
            i = strtol(q, &p, 10);
            if (q == p) {
                SSH_LOG(SSH_LOG_DEBUG, "No log verbositiy was parsed");
                SAFE_FREE(q);
                return -1;
            }
            SAFE_FREE(q);

            ssh_set_log_level(i & 0xffffU);
        }
        break;
    case SSH_BIND_OPTIONS_BANNER:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            SAFE_FREE(sshbind->banner);
            sshbind->banner = strdup(value);
            if (sshbind->banner == NULL) {
                ssh_set_error_oom(sshbind);
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_CIPHERS_C_S:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            rc = ssh_bind_set_algo(sshbind,
                                   SSH_CRYPT_C_S,
                                   v,
                                   &wanted_methods[SSH_CRYPT_C_S]);
            if (rc < 0) {
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_CIPHERS_S_C:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            rc = ssh_bind_set_algo(sshbind,
                                   SSH_CRYPT_S_C,
                                   v,
                                   &wanted_methods[SSH_CRYPT_S_C]);
            if (rc < 0) {
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_KEY_EXCHANGE:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            rc = ssh_bind_set_algo(sshbind,
                                   SSH_KEX,
                                   v,
                                   &wanted_methods[SSH_KEX]);
            if (rc < 0) {
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_HMAC_C_S:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            rc = ssh_bind_set_algo(sshbind,
                                   SSH_MAC_C_S,
                                   v,
                                   &wanted_methods[SSH_MAC_C_S]);
            if (rc < 0) {
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_HMAC_S_C:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            rc = ssh_bind_set_algo(sshbind,
                                   SSH_MAC_S_C,
                                   v,
                                   &wanted_methods[SSH_MAC_S_C]);
            if (rc < 0) {
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_CONFIG_DIR:
        v = value;
        SAFE_FREE(sshbind->config_dir);
        if (v == NULL) {
            break;
        } else if (v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            sshbind->config_dir = ssh_path_expand_tilde(v);
            if (sshbind->config_dir == NULL) {
                ssh_set_error_oom(sshbind);
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            rc = ssh_bind_set_algo(sshbind,
                                   SSH_HOSTKEYS,
                                   v,
                                   &sshbind->pubkey_accepted_key_types);
            if (rc < 0) {
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            rc = ssh_bind_set_algo(sshbind,
                                   SSH_HOSTKEYS,
                                   v,
                                   &wanted_methods[SSH_HOSTKEYS]);
            if (rc < 0) {
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_PROCESS_CONFIG:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            bool *x = (bool *)value;
            sshbind->config_processed = !(*x);
        }
        break;
    case SSH_BIND_OPTIONS_MODULI:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            SAFE_FREE(sshbind->moduli_file);
            sshbind->moduli_file = strdup(value);
            if (sshbind->moduli_file == NULL) {
                ssh_set_error_oom(sshbind);
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_RSA_MIN_SIZE:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            int *x = (int *)value;

            if (*x < 0) {
                ssh_set_error_invalid(sshbind);
                return -1;
            }

            /* (*x == 0) is allowed as it is used to revert to default */

            if (*x > 0 && *x < RSA_MIN_KEY_SIZE) {
                ssh_set_error(sshbind,
                              SSH_REQUEST_DENIED,
                              "The provided value (%d) for minimal RSA key "
                              "size is too small. Use at least %d bits.",
                              *x,
                              RSA_MIN_KEY_SIZE);
                return -1;
            }
            sshbind->rsa_min_size = *x;
        }
        break;
#ifdef WITH_GSSAPI
    case SSH_BIND_OPTIONS_GSSAPI_KEY_EXCHANGE:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            bool *x = (bool *)value;
            sshbind->gssapi_key_exchange = *x;
        }
        break;
    case SSH_BIND_OPTIONS_GSSAPI_KEY_EXCHANGE_ALGS:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            char *ret = NULL;
            SAFE_FREE(sshbind->gssapi_key_exchange_algs);
            ret = ssh_find_all_matching(GSSAPI_KEY_EXCHANGE_SUPPORTED, value);
            if (ret == NULL) {
                ssh_set_error(
                    sshbind,
                    SSH_REQUEST_DENIED,
                    "GSSAPI key exchange algorithms not supported or invalid");
                return -1;
            }
            sshbind->gssapi_key_exchange_algs = ret;
        }
        break;
#endif /* WITH_GSSAPI */
    default:
        ssh_set_error(sshbind,
                      SSH_REQUEST_DENIED,
                      "Unknown ssh option %d",
                      type);
        return -1;
        break;
    }

    return 0;
}

static char *ssh_bind_options_expand_escape(ssh_bind sshbind, const char *s)
{
    char *buf = NULL;
    char *r = NULL;
    char *x = NULL;
    const char *p = NULL;
    size_t i, l;

    r = ssh_path_expand_tilde(s);
    if (r == NULL) {
        ssh_set_error_oom(sshbind);
        return NULL;
    }

    if (strlen(r) > MAX_BUF_SIZE) {
        ssh_set_error(sshbind, SSH_FATAL, "string to expand too long");
        free(r);
        return NULL;
    }

    buf = malloc(MAX_BUF_SIZE);
    if (buf == NULL) {
        ssh_set_error_oom(sshbind);
        free(r);
        return NULL;
    }

    p = r;
    buf[0] = '\0';

    for (i = 0; *p != '\0'; p++) {
        if (*p != '%') {
            buf[i] = *p;
            i++;
            if (i >= MAX_BUF_SIZE) {
                free(buf);
                free(r);
                return NULL;
            }
            buf[i] = '\0';
            continue;
        }

        p++;
        if (*p == '\0') {
            break;
        }

        switch (*p) {
            case 'd':
                x = strdup(sshbind->config_dir);
                break;
            default:
                ssh_set_error(sshbind, SSH_FATAL,
                        "Wrong escape sequence detected");
                free(buf);
                free(r);
                return NULL;
        }

        if (x == NULL) {
            ssh_set_error_oom(sshbind);
            free(buf);
            free(r);
            return NULL;
        }

        i += strlen(x);
        if (i >= MAX_BUF_SIZE) {
            ssh_set_error(sshbind, SSH_FATAL,
                    "String too long");
            free(buf);
            free(x);
            free(r);
            return NULL;
        }
        l = strlen(buf);
        strlcpy(buf + l, x, MAX_BUF_SIZE - l);
        buf[i] = '\0';
        SAFE_FREE(x);
    }

    free(r);

    /* strip the unused space by realloc */
    x = realloc(buf, strlen(buf) + 1);
    if (x == NULL) {
        ssh_set_error_oom(sshbind);
        free(buf);
    }
    return x;
}

/**
 * @brief Parse a ssh bind options configuration file.
 *
 * This parses the options file and set them to the ssh_bind handle provided. If
 * an option was previously set, it is overridden. If the global configuration
 * hasn't been processed yet, it is processed prior to the provided file.
 *
 * @param  sshbind      SSH bind handle
 *
 * @param  filename     The options file to use; if NULL only the global
 *                      configuration is parsed and applied (if it hasn't been
 *                      processed before).
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_bind_options_parse_config(ssh_bind sshbind, const char *filename)
{
    int rc = 0;
    char *expanded_filename = NULL;

    if (sshbind == NULL) {
        return -1;
    }

    /* If the global default configuration hasn't been processed yet, process it
     * before the provided configuration. */
    if (!(sshbind->config_processed)) {
        if (ssh_file_readaccess_ok(GLOBAL_BIND_CONFIG)) {
            rc = ssh_bind_config_parse_file(sshbind, GLOBAL_BIND_CONFIG);
#ifdef USR_GLOBAL_BIND_CONFIG
        } else {
            rc = ssh_bind_config_parse_file(sshbind, USR_GLOBAL_BIND_CONFIG);
#endif
        }
        if (rc != 0) {
            return rc;
        }
        sshbind->config_processed = true;
    }

    if (filename != NULL) {
        expanded_filename = ssh_bind_options_expand_escape(sshbind, filename);
        if (expanded_filename == NULL) {
            return -1;
        }

        /* Apply the user provided configuration */
        rc = ssh_bind_config_parse_file(sshbind, expanded_filename);
        free(expanded_filename);
    }

    return rc;
}

#endif

/** @} */
