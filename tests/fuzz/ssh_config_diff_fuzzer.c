#define _GNU_SOURCE
#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define LIBSSH_STATIC 1
#include <libssh/config.h>
#include <libssh/config_parser.h>
#include <libssh/libssh.h>
#include <libssh/options.h>
#include <libssh/priv.h>
#include <libssh/session.h>

#ifndef MAX_LINE_SIZE
#define MAX_LINE_SIZE 1024
#endif

struct ssh_config_values {
    char *user;
    char *host;
    char *port;
    char *identities_only;
    char *bind_address;
    char *certificate_file;
    char *identity_file;
    char *identity_agent;
    char *rekey_limit;
    char *password_auth;
    char *known_hosts;
    char *global_known_hosts;
    char *connect_timeout;
    char *address_family;
    char *server_alive_count_max;
    char *server_alive_interval;
    char *strict_host_key_checking;
    char *ciphers;
    char *macs;
    char *kex_algorithms;
};

/* Returns true if c can appear in a token that might contain a keyword
 * as a substring. SSH config keywords are purely alphabetical, but values
 * (e.g. hostnames like "foo-port.bar.com" or "my_host") can contain
 * '-' and '_'. Treating these as word-continuing characters prevents
 * false matches when a keyword substring appears inside a value.
 *
 * Note: This check is currently insufficient because it does not account
 * for other characters like commas which, when alongside a keyword, make
 * it obvious that it is just a part of a value. This known limitation
 * may lead to false positive divergences.
 */
static inline bool is_invalid_char_next_to_keyword(char c)
{
    return isalnum((unsigned char)c) || c == '_' || c == '-';
}

/* Check if input config explicitly contains a keyword (case-insensitive) */
static bool contains_keyword(const char *input, const char *keyword)
{
    const char *p = input;
    size_t len = strlen(keyword);
    bool match;
    char c;

    while ((p = strcasestr(p, keyword)) != NULL) {
        match = true;
        /* Check preceding char */
        if (p > input) {
            c = *(p - 1);
            if (is_invalid_char_next_to_keyword(c)) {
                match = false;
            }
        }
        /* Check succeeding char */
        if (match) {
            c = p[len];
            if (is_invalid_char_next_to_keyword(c)) {
                match = false;
            }
        }
        if (match) {
            return true;
        }
        p += len;
    }
    return false;
}

/* Helper to append an entry to a newline-separated config value list */
static void config_value_list_append(char **list, const char *entry)
{
    size_t list_len, entry_len;
    char *new_list = NULL;

    if (entry == NULL) {
        return;
    }

    if (*list == NULL) {
        *list = strdup(entry);
        return;
    }

    list_len = strlen(*list);
    entry_len = strlen(entry);

    new_list = realloc(*list, list_len + 1 + entry_len + 1);
    if (new_list == NULL) {
        return;
    }

    new_list[list_len] = '\n';
    memcpy(new_list + list_len + 1, entry, entry_len + 1);
    *list = new_list;
}

/*
 * Filter to skip odd and unrealistic config inputs.
 * Returns true if the config buffer looks like a plausible SSH config,
 * false if it contains odd characters or dangerous keywords.
 */
static bool is_valid_config_input(const char *input, size_t size)
{
    size_t line_len = 0;
    size_t i;
    unsigned char c;
    const char *p = input;
    const char *end = input + size;

    /* Reject inputs containing non-printable characters (except \n, \r, \t) */
    for (i = 0; i < size; i++) {
        c = input[i];
        if (c != '\n' && c != '\r' && c != '\t' && !isprint(c)) {
            return false;
        }

        /* Fast check for unsupported OpenSSH expansion tokens */
        if (c == '%' && i + 1 < size) {
            char next = input[i + 1];
            if (next == 'k' || next == 'K' || next == 'i' || next == 'I' || 
                next == 'f' || next == 't' || next == 'H' || next == 'T' || next == 'L') {
                return false; /* Skip because libssh does not support these tokens yet */
            }
        }
    }

    while (p < end && *p) {
        /* Skip leading whitespace */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }
        
        if (p >= end || !*p) break;

        /* Skip comment lines */
        if (*p == '#') {
            while (p < end && *p && *p != '\n') p++;
            if (p < end && *p == '\n') p++;
            continue;
        }

        /* Check line length limit */
        const char *eol = strchr(p, '\n');
        line_len = eol ? (size_t)(eol - p) : (size_t)(end - p);
        if (line_len > MAX_LINE_SIZE) {
            return false;
        }

        /* Find the end of the keyword (first space, tab, =, or newline) */
        const char *delim = strpbrk(p, " \t=\n");
        const char *quote = strchr(p, '"');
        
        /* If a quote appears before the keyword delimiter, it's an
         * OpenSSH edgecase and it should be ignored.
         */
        if (quote && (!delim || quote < delim)) {
            return false;
        }
        
        /* Jump to the next line */
        p += line_len;
        if (p < end && *p == '\n') p++;
    }

    /* Block specific keywords that break the fuzzer */
    const char *unsafe_keywords[] = {
        "exec",         /* Prevents arbitrary shell execution */
        "proxycommand", /* Prevents arbitrary shell execution */
        "localcommand", /* Prevents arbitrary shell execution */
        "include" /* Prevents file system traversal and random file inclusions
                   */
    };

    for (size_t k = 0; k < sizeof(unsafe_keywords) / sizeof(unsafe_keywords[0]);
         k++) {
        if (contains_keyword(input, unsafe_keywords[k])) {
            return false;
        }
    }

    return true;
}

/* Get parsed config value from OpenSSH */
int get_all_openssh_values(const char *config_path,
                           const char *target_host,
                           struct ssh_config_values *values)
{
    char cmd[MAX_LINE_SIZE], line[MAX_LINE_SIZE];
    FILE *pipe = NULL;
    char *keyword = NULL;
    char **target_ptr = NULL;
    enum ssh_config_opcode_e opcode;

    snprintf(cmd,
             sizeof(cmd),
             "ssh -G -F '%s' '%s' 2>/dev/null",
             config_path,
             target_host);

    pipe = popen(cmd, "r");
    if (!pipe) {
        return -1;
    }

    /* Read each line from the pipe one by one */
    while (fgets(line, sizeof(line), pipe)) {

        /* Ignore empty lines and comments */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        char *space = strchr(line, ' ');
        if (space == NULL) {
            continue;
        }

        *space = '\0';
        keyword = line;

        /* Get the opcode from the keyword to use switch case */
        opcode = ssh_config_get_opcode(keyword);

        /* Use switch case to handle different opcodes */
        switch (opcode) {
        case SOC_USERNAME:
            target_ptr = &values->user;
            break;
        case SOC_HOSTNAME:
            target_ptr = &values->host;
            break;
        case SOC_PORT:
            target_ptr = &values->port;
            break;
        case SOC_IDENTITIESONLY:
            target_ptr = &values->identities_only;
            break;
        case SOC_IDENTITY:
            target_ptr = &values->identity_file;
            break;
        case SOC_BINDADDRESS:
            target_ptr = &values->bind_address;
            break;
        case SOC_CERTIFICATE:
            target_ptr = &values->certificate_file;
            break;
        case SOC_IDENTITYAGENT:
            target_ptr = &values->identity_agent;
            break;
        case SOC_REKEYLIMIT:
            target_ptr = &values->rekey_limit;
            break;
        case SOC_PASSWORDAUTHENTICATION:
            target_ptr = &values->password_auth;
            break;
        case SOC_KNOWNHOSTS:
            target_ptr = &values->known_hosts;
            break;
        case SOC_GLOBALKNOWNHOSTSFILE:
            target_ptr = &values->global_known_hosts;
            break;
        case SOC_TIMEOUT:
            target_ptr = &values->connect_timeout;
            break;
        case SOC_CIPHERS:
            target_ptr = &values->ciphers;
            break;
        case SOC_MACS:
            target_ptr = &values->macs;
            break;
        case SOC_KEXALGORITHMS:
            target_ptr = &values->kex_algorithms;
            break;
        case SOC_ADDRESSFAMILY:
            target_ptr = &values->address_family;
            break;
        case SOC_SERVERALIVECOUNTMAX:
            target_ptr = &values->server_alive_count_max;
            break;
        case SOC_SERVERALIVEINTERVAL:
            target_ptr = &values->server_alive_interval;
            break;
        case SOC_STRICTHOSTKEYCHECK:
            target_ptr = &values->strict_host_key_checking;
            break;
        default:
            continue;
        }

        /* If no target pointer was mapped, skip this config line */
        if (target_ptr == NULL) {
            continue;
        }

        bool is_list = (opcode == SOC_IDENTITY || opcode == SOC_CERTIFICATE);

        /* OpenSSH only uses the first value it sees for these options, so
         * ignore any duplicates */
        if (!is_list && *target_ptr != NULL) {
            continue;
        }

        char *extracted_value = space + 1;
        char *newline = strchr(extracted_value, '\n');
        if (newline) {
            *newline = '\0';
        }

        if (is_list) {
            /* Append to the newline-separated string list */
            config_value_list_append(target_ptr, extracted_value);
        } else if (strcasecmp(extracted_value, "true") == 0) {
            *target_ptr = strdup("yes");
        } else if (strcasecmp(extracted_value, "false") == 0) {
            *target_ptr = strdup("no");
        } else {
            *target_ptr = strdup(extracted_value);
        }
    }
    return pclose(pipe);
}

/* Get parsed config value from libssh */
int get_all_libssh_values(ssh_session session,
                          struct ssh_config_values *values)
{
    unsigned int port = 0;
    char buf[32];
    char rekey_buf[64];
    int int_val = 0;

    int rc;

    rc = ssh_options_get(session, SSH_OPTIONS_USER, &values->user);
    if (rc != SSH_OK) {
        return rc;
    }

    rc = ssh_options_get(session, SSH_OPTIONS_HOST, &values->host);
    if (rc != SSH_OK) {
        return rc;
    }

    rc = ssh_options_get(session, SSH_OPTIONS_CIPHERS_C_S, &values->ciphers);
    if (rc != SSH_OK) {
        return rc;
    }

    rc = ssh_options_get(session, SSH_OPTIONS_HMAC_C_S, &values->macs);
    if (rc != SSH_OK) {
        return rc;
    }

    rc = ssh_options_get(session, SSH_OPTIONS_KEY_EXCHANGE, &values->kex_algorithms);
    if (rc != SSH_OK) {
        return rc;
    }

    rc = ssh_options_get_port(session, &port);
    if (rc == SSH_OK) {
        snprintf(buf, sizeof(buf), "%u", port);
        values->port = strdup(buf);
        if (values->port == NULL) {
            return SSH_ERROR;
        }
    } else {
        return rc;
    }

    /* IdentitiesOnly */
    values->identities_only =
        strdup(session->opts.identities_only ? "yes" : "no");
    if (values->identities_only == NULL) {
        return SSH_ERROR;
    }

    /* BindAddress */
    if (session->opts.bindaddr != NULL) {
        values->bind_address = strdup(session->opts.bindaddr);
        if (values->bind_address == NULL) {
            return SSH_ERROR;
        }
    }

    /* IdentityAgent */
    if (session->opts.agent_socket != NULL) {
        values->identity_agent = strdup(session->opts.agent_socket);
        if (values->identity_agent == NULL) {
            return SSH_ERROR;
        }
    }

    /* RekeyLimit: format as "bytes seconds" */
    snprintf(rekey_buf,
             sizeof(rekey_buf),
             "%llu %u",
             (unsigned long long)session->opts.rekey_data,
             (unsigned int)(session->opts.rekey_time / 1000));
    values->rekey_limit = strdup(rekey_buf);
    if (values->rekey_limit == NULL) {
        return SSH_ERROR;
    }

    /* PasswordAuthentication */
    values->password_auth = strdup(
        (session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH) ? "yes" : "no");
    if (values->password_auth == NULL) {
        return SSH_ERROR;
    }

    /* UserKnownHostsFile */
    (void)ssh_options_get(session,
                          SSH_OPTIONS_KNOWNHOSTS,
                          &values->known_hosts);

    /* GlobalKnownHostsFile */
    (void)ssh_options_get(session,
                          SSH_OPTIONS_GLOBAL_KNOWNHOSTS,
                          &values->global_known_hosts);

    /* ConnectTimeout (Integer) */
    if (session->opts.timeout == 0 && session->opts.options_seen[SOC_TIMEOUT] == 0) {
        values->connect_timeout = strdup("none");
    } else {
        char buf2[32];
        snprintf(buf2, sizeof(buf2), "%lu", session->opts.timeout);
        values->connect_timeout = strdup(buf2);
    }
    if (values->connect_timeout == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_options_get_int(session, SSH_OPTIONS_ADDRESS_FAMILY, &int_val);
    if (rc == SSH_OK) {
        if (int_val == SSH_ADDRESS_FAMILY_ANY) {
            values->address_family = strdup("any");
        } else if (int_val == SSH_ADDRESS_FAMILY_INET) {
            values->address_family = strdup("inet");
        } else if (int_val == SSH_ADDRESS_FAMILY_INET6) {
            values->address_family = strdup("inet6");
        }
    }

    rc = ssh_options_get_int(session, SSH_OPTIONS_SERVER_ALIVE_COUNT_MAX, &int_val);
    if (rc == SSH_OK) {
        snprintf(buf, sizeof(buf), "%d", int_val);
        values->server_alive_count_max = strdup(buf);
    }

    rc = ssh_options_get_int(session, SSH_OPTIONS_SERVER_ALIVE_INTERVAL, &int_val);
    if (rc == SSH_OK) {
        snprintf(buf, sizeof(buf), "%d", int_val);
        values->server_alive_interval = strdup(buf);
    }

    rc = ssh_options_get_int(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &int_val);
    if (rc == SSH_OK) {
        if (int_val == SSH_STRICT_HOSTKEY_YES) {
            values->strict_host_key_checking = strdup("yes");
        } else if (int_val == SSH_STRICT_HOSTKEY_OFF) {
            values->strict_host_key_checking = strdup("no");
        } else if (int_val == SSH_STRICT_HOSTKEY_ASK) {
            values->strict_host_key_checking = strdup("ask");
        } else if (int_val == SSH_STRICT_HOSTKEY_ACCEPT_NEW) {
            values->strict_host_key_checking = strdup("accept-new");
        }
    }

    return SSH_OK;
}

/* Free parsed config values */
void ssh_config_values_free(struct ssh_config_values *values)
{
    if (values == NULL) {
        return;
    }
    SAFE_FREE(values->user);
    SAFE_FREE(values->host);
    SAFE_FREE(values->port);
    SAFE_FREE(values->identities_only);
    SAFE_FREE(values->bind_address);
    SAFE_FREE(values->certificate_file);
    SAFE_FREE(values->identity_file);
    SAFE_FREE(values->identity_agent);
    SAFE_FREE(values->rekey_limit);
    SAFE_FREE(values->password_auth);
    SAFE_FREE(values->known_hosts);
    SAFE_FREE(values->global_known_hosts);
    SAFE_FREE(values->connect_timeout);
    SAFE_FREE(values->address_family);
    SAFE_FREE(values->server_alive_count_max);
    SAFE_FREE(values->server_alive_interval);
    SAFE_FREE(values->strict_host_key_checking);
    SAFE_FREE(values->ciphers);
    SAFE_FREE(values->macs);
    SAFE_FREE(values->kex_algorithms);
}

#ifdef FUZZ_CONTINUOUS_MODE
/* djb2 string hashing algorithm for unique divergence filenames to avoid
 * duplication of corpus when the fuzzer is rerun and the same corpus is fed
 * again */
static unsigned long hash_djb2(const char *str)
{
    unsigned long hash = 5381;
    int c;

    if (str == NULL) {
        return 0;
    }

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}
#endif

static void write_divergence_details(FILE *out,
                                     const char *input,
                                     const char *key,
                                     const char *libssh_val,
                                     const char *openssh_val)
{
    fprintf(out, "Input Config file:\n---\n%s\n---\n", input);
    fprintf(out, "Key             : %s\n", key);
    fprintf(out, "libssh parsed   : [%s]\n", libssh_val ? libssh_val : "NULL");
    fprintf(out,
            "OpenSSH parsed  : [%s]\n",
            openssh_val ? openssh_val : "NULL");
}

/* Print divergence information and log to filesystem */
void print_divergence_and_fail(const char *input,
                               const char *key,
                               const char *libssh_val,
                               const char *openssh_val)
{
#ifdef FUZZ_CONTINUOUS_MODE
    char dir_path[256];
    char file_path[512];
    FILE *f = NULL;
    unsigned long hash;
#endif

    fprintf(stderr, "\n================ DIVERGENCE FOUND ================\n");
    write_divergence_details(stderr, input, key, libssh_val, openssh_val);
    fprintf(stderr, "==================================================\n");

#ifndef FUZZ_CONTINUOUS_MODE
    assert(0);
#else
    /* Ensure root bugs directory exists with Read/Write/Execute permissions for owner */
    mkdir("bugs", S_IRWXU);

    /* Create subfolder for this specific option key */
    snprintf(dir_path, sizeof(dir_path), "bugs/%s", key);
    mkdir(dir_path, S_IRWXU);

    /* Generate unique filename based on the input hash */
    hash = hash_djb2(input);
    snprintf(file_path, sizeof(file_path), "%s/%lu.txt", dir_path, hash);

    /* Write divergence details to file */
    f = fopen(file_path, "w");
    if (f != NULL) {
        write_divergence_details(f, input, key, libssh_val, openssh_val);
        fclose(f);
    }
#endif
}

/* Compare parsed config values */
void assert_libssh_openssh_value_equal(const char *input,
                                       const char *key,
                                       const char *libssh_val,
                                       const char *openssh_val)
{
    if (libssh_val && openssh_val) {
        if (strcmp(libssh_val, openssh_val) != 0) {
            const char *eq = strchr(openssh_val, '=');
            if (eq != NULL) {
                size_t prefix_len = eq - openssh_val;
                if (strncmp(libssh_val, openssh_val, prefix_len) == 0 &&
                    libssh_val[prefix_len] == '\0') {
                    return; /* Ignore divergence: known libssh tokenizer truncation */
                }
            }
            if (strcmp(key, "UserKnownHostsFile") == 0 || strcmp(key, "GlobalKnownHostsFile") == 0) {
                size_t libssh_len = strlen(libssh_val);
                if (strncmp(openssh_val, libssh_val, libssh_len) == 0 &&
                    (openssh_val[libssh_len] == ' ' || openssh_val[libssh_len] == '\0')) {
                    return; /* Ignore divergence: libssh only parses the first file, OpenSSH parses multiple */
                }
            }
            print_divergence_and_fail(input, key, libssh_val, openssh_val);
        }
    } else if ((libssh_val == NULL) != (openssh_val == NULL)) {
        /* Edge case for libssh tokenizer truncation: If a value starts with '=', 
         * libssh's tokenizer stops immediately and returns an empty string, 
         * which is then converted to NULL. OpenSSH preserves it. 
         * For example: 'BindAddress==' -> OpenSSH gets '=' and libssh gets NULL. */
        if (libssh_val == NULL && openssh_val != NULL && openssh_val[0] == '=') {
            return; /* Ignore divergence: known libssh tokenizer truncation */
        }
        print_divergence_and_fail(input, key, libssh_val, openssh_val);
    }
}

/* Order insensitive comparison for comma separated lists.
 * This is used to compare the values of the 'Ciphers', 'MACs', and
 * 'KexAlgorithms' options because their unexpanded wildcard lists might be
 * parsed in a slightly different internal order.
 */
static bool is_subset_of_comma_list(const char *subset_str,
                                    const char *superset_str)
{
    char *subset_copy = strdup(subset_str);
    char *subset_saveptr, *superset_saveptr;
    char *current_subset_item, *current_superset_item;
    bool all_items_found = true;

    if (subset_copy == NULL) {
        return false;
    }

    for (current_subset_item = strtok_r(subset_copy, ",", &subset_saveptr);
         current_subset_item != NULL;
         current_subset_item = strtok_r(NULL, ",", &subset_saveptr)) {

        bool item_found_in_superset = false;
        char *superset_copy = strdup(superset_str);

        if (superset_copy == NULL) {
            free(subset_copy);
            return false;
        }

        for (current_superset_item =
                 strtok_r(superset_copy, ",", &superset_saveptr);
             current_superset_item != NULL;
             current_superset_item = strtok_r(NULL, ",", &superset_saveptr)) {

            if (strcmp(current_subset_item, current_superset_item) == 0) {
                item_found_in_superset = true;
                break;
            }
        }
        free(superset_copy);

        if (!item_found_in_superset) {
            all_items_found = false;
            break;
        }
    }

    free(subset_copy);
    return all_items_found;
}

static bool is_permutation_of_comma_list(const char *s1, const char *s2)
{
    if (s1 == NULL && s2 == NULL)
        return true;
    if (s1 == NULL || s2 == NULL)
        return false;

    return is_subset_of_comma_list(s1, s2) && is_subset_of_comma_list(s2, s1);
}

void assert_libssh_openssh_list_equal(const char *input,
                                      const char *key,
                                      const char *libssh_val,
                                      const char *openssh_val)
{
    if (!is_permutation_of_comma_list(libssh_val, openssh_val)) {
        print_divergence_and_fail(input, key, libssh_val, openssh_val);
    }
}

/* Initialize the fuzzer */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    ssh_init();
    return 0;
}

/*
 * Main fuzzer entry point
 *
 * Input format:
 *   Line 1 : Target hostname (everything before the first '\n')
 *   Rest   : The raw SSH configuration content to be parsed
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ssh_session session = NULL;
    char *input = NULL;
    const char *newline = NULL;
    char temp_cfg[] = "/tmp/fuzz_config_XXXXXX";
    char target_host[256];
    char *pre_apply_identity = NULL;
    char *pre_apply_certificate = NULL;
    struct ssh_config_values openssh_values = {0};
    struct ssh_config_values libssh_values = {0};
    struct ssh_list *id_list = NULL;
    struct ssh_list *cert_list = NULL;
    struct ssh_iterator *it = NULL;
    size_t host_len = 0;
    size_t config_size = 0;
    size_t i = 0;
    int fd = -1;
    int rc = 0;

    if (size < 2) {
        return 0;
    }

    if (size > 4096) {
        return 0;
    }

    /* Find the first newline — it separates the hostname from the config */
    newline = memchr(data, '\n', size);
    if (newline == NULL) {
        return 0; /* No newline means no config content */
    }

    host_len = (size_t)(newline - (const char *)data);
    if (host_len == 0 || host_len >= sizeof(target_host)) {
        return 0;
    }

    memcpy(target_host, data, host_len);
    target_host[host_len] = '\0';

    /* Sanitize target_host to prevent shell injection in popen() */
    for (i = 0; i < host_len; i++) {
        if (!isalnum((unsigned char)target_host[i]) && target_host[i] != '.' &&
            target_host[i] != '-' && target_host[i] != '_') {
            target_host[i] = 'x';
        }
        target_host[i] = tolower((unsigned char)target_host[i]);
    }

    /* Config content starts after the newline */
    config_size = size - host_len - 1;
    if (config_size == 0) {
        return 0;
    }

    input = (char *)malloc(config_size + 1);
    if (!input) {
        return 0;
    }

    memcpy(input, newline + 1, config_size);
    input[config_size] = '\0';

    /* Skip odd config inputs and dangerous keywords */
    if (!is_valid_config_input(input, config_size)) {
        SAFE_FREE(input);
        return 0;
    }

    fd = mkstemp(temp_cfg);
    if (fd == -1) {
        SAFE_FREE(input);
        return 0;
    }

    if (write(fd, input, config_size) != (ssize_t)config_size) {
        close(fd);
        goto cleanup;
    }
    close(fd);

    session = ssh_new();
    if (!session) {
        goto cleanup;
    }

    /* Dynamically count the pre-loaded default identity files so we can
     * distinguish them from config-added entries later. */
    size_t n_default_ids = 0;
    if (session->opts.identity != NULL) {
        n_default_ids = ssh_list_count(session->opts.identity);
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, target_host) != SSH_OK) {
        goto cleanup;
    }

    ssh_config_parse_file(session, temp_cfg);

    /*
     * Store the identity files and certificate files literals BEFORE
     * ssh_options_apply expands tildes and tokens.
     */
    id_list = session->opts.identity_non_exp;
    cert_list = session->opts.certificate_non_exp;
    it = NULL;

    if (cert_list != NULL) {
        it = ssh_list_get_iterator(cert_list);
        while (it) {
            config_value_list_append(&pre_apply_certificate,
                                     ssh_iterator_value(char *, it));
            it = it->next;
        }
    }

    if (id_list != NULL) {
        size_t total_ids = ssh_list_count(id_list);
        size_t n_config_ids =
            (total_ids > n_default_ids) ? (total_ids - n_default_ids) : 0;
        if (n_config_ids > 0) {
            char **tmp_ids = calloc(n_config_ids, sizeof(char *));
            if (tmp_ids != NULL) {
                it = ssh_list_get_iterator(id_list);
                for (size_t j = 0; j < n_config_ids; j++) {
                    tmp_ids[j] = ssh_iterator_value(char *, it);
                    it = it->next;
                }
                for (size_t j = 0; j < n_config_ids; j++) {
                    config_value_list_append(&pre_apply_identity,
                                             tmp_ids[n_config_ids - 1 - j]);
                }
                SAFE_FREE(tmp_ids);
            }
        }
    }

    ssh_options_apply(session);

    get_all_libssh_values(session, &libssh_values);

    /*
     * Override identity_file and certificate_file with the unexpanded literal
     */
    if (pre_apply_identity != NULL) {
        SAFE_FREE(libssh_values.identity_file);
        libssh_values.identity_file = pre_apply_identity;
        pre_apply_identity = NULL;
    }
    if (pre_apply_certificate != NULL) {
        SAFE_FREE(libssh_values.certificate_file);
        libssh_values.certificate_file = pre_apply_certificate;
        pre_apply_certificate = NULL;
    }

    rc = get_all_openssh_values(temp_cfg, target_host, &openssh_values);

    /* Skip comparison if OpenSSH failed entirely.
     * This means OpenSSH's ssh -G rejected the entire config file due to
     * validation failures, not a config parsing divergence. OpenSSH is stricter
     * and may reject configs that libssh successfully parses. */
    if (rc != 0) {
        goto cleanup;
    }
    if (contains_keyword(input, "addressfamily")) {
        if (session->opts.options_seen[SOC_ADDRESSFAMILY] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "AddressFamily",
                                              libssh_values.address_family,
                                              openssh_values.address_family);
        }
    }

    if (contains_keyword(input, "serveralivecountmax")) {
        if (session->opts.options_seen[SOC_SERVERALIVECOUNTMAX] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "ServerAliveCountMax",
                                              libssh_values.server_alive_count_max,
                                              openssh_values.server_alive_count_max);
        }
    }

    if (contains_keyword(input, "serveraliveinterval")) {
        if (session->opts.options_seen[SOC_SERVERALIVEINTERVAL] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "ServerAliveInterval",
                                              libssh_values.server_alive_interval,
                                              openssh_values.server_alive_interval);
        }
    }

    if (contains_keyword(input, "stricthostkeychecking")) {
        if (session->opts.options_seen[SOC_STRICTHOSTKEYCHECK] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "StrictHostKeyChecking",
                                              libssh_values.strict_host_key_checking,
                                              openssh_values.strict_host_key_checking);
        }
    }

    if (contains_keyword(input, "ciphers")) {
        if (session->opts.options_seen[SOC_CIPHERS] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "Ciphers",
                                              libssh_values.ciphers,
                                              openssh_values.ciphers);
        }
    }

    if (contains_keyword(input, "macs")) {
        if (session->opts.options_seen[SOC_MACS] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "MACs",
                                              libssh_values.macs,
                                              openssh_values.macs);
        }
    }

    if (contains_keyword(input, "kexalgorithms")) {
        if (session->opts.options_seen[SOC_KEXALGORITHMS] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "KexAlgorithms",
                                              libssh_values.kex_algorithms,
                                              openssh_values.kex_algorithms);
        }
    }

    if (contains_keyword(input, "user")) {
        assert_libssh_openssh_value_equal(input,
                                          "User",
                                          libssh_values.user,
                                          openssh_values.user);
    }

    if (contains_keyword(input, "hostname")) {
        assert_libssh_openssh_value_equal(input,
                                          "HostName",
                                          libssh_values.host,
                                          openssh_values.host);
    }

    if (contains_keyword(input, "port")) {
        assert_libssh_openssh_value_equal(input,
                                          "Port",
                                          libssh_values.port,
                                          openssh_values.port);
    }

    /* Only compare IdentitiesOnly when explicitly set in the config. */
    if (contains_keyword(input, "identitiesonly")) {
        assert_libssh_openssh_value_equal(input,
                                          "IdentitiesOnly",
                                          libssh_values.identities_only,
                                          openssh_values.identities_only);
    }

    if (contains_keyword(input, "bindaddress")) {
        if (session->opts.options_seen[SOC_BINDADDRESS] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "BindAddress",
                                              libssh_values.bind_address,
                                              openssh_values.bind_address);
        }
    }

    if (contains_keyword(input, "certificatefile")) {
        if (session->opts.options_seen[SOC_CERTIFICATE] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "CertificateFile",
                                              libssh_values.certificate_file,
                                              openssh_values.certificate_file);
        }
    }

    if (contains_keyword(input, "identityagent")) {
        if (session->opts.options_seen[SOC_IDENTITYAGENT] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "IdentityAgent",
                                              libssh_values.identity_agent,
                                              openssh_values.identity_agent);
        }
    }

    if (contains_keyword(input, "rekeylimit")) {
        if (session->opts.options_seen[SOC_REKEYLIMIT] == 1) {
            if (openssh_values.rekey_limit != NULL) {
                char *space = strchr(openssh_values.rekey_limit, ' ');
                if (space != NULL) {
                    long long openssh_time = strtoll(space + 1, NULL, 10);
                    if (openssh_time > (UINT32_MAX / 1000)) {
                        goto cleanup; /* Skip, libssh doesn't support > 49.7 days */
                    }
                }
            }
            assert_libssh_openssh_value_equal(input,
                                              "RekeyLimit",
                                              libssh_values.rekey_limit,
                                              openssh_values.rekey_limit);
        }
    }

    if (contains_keyword(input, "passwordauthentication")) {
        assert_libssh_openssh_value_equal(input,
                                          "PasswordAuthentication",
                                          libssh_values.password_auth,
                                          openssh_values.password_auth);
    }

    if (contains_keyword(input, "userknownhostsfile")) {
        if (session->opts.options_seen[SOC_KNOWNHOSTS] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "UserKnownHostsFile",
                                              libssh_values.known_hosts,
                                              openssh_values.known_hosts);
        }
    }

    if (contains_keyword(input, "globalknownhostsfile")) {
        if (session->opts.options_seen[SOC_GLOBALKNOWNHOSTSFILE] == 1) {
            assert_libssh_openssh_value_equal(
                input,
                "GlobalKnownHostsFile",
                libssh_values.global_known_hosts,
                openssh_values.global_known_hosts);
        }
    }

    if (contains_keyword(input, "connecttimeout")) {
        if (session->opts.options_seen[SOC_TIMEOUT] == 1) {
            assert_libssh_openssh_value_equal(input,
                                              "ConnectTimeout",
                                              libssh_values.connect_timeout,
                                              openssh_values.connect_timeout);
        }
    }

cleanup:
    ssh_config_values_free(&openssh_values);
    ssh_config_values_free(&libssh_values);
    SAFE_FREE(pre_apply_identity);
    SAFE_FREE(pre_apply_certificate);
    SAFE_FREE(input);
    ssh_free(session);
    unlink(temp_cfg);
    return 0;
}
