/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Andreas Schneider
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

#define LIBSSH_STATIC

#include "torture.h"
#include "torture_key.h"

#include <sys/types.h>
#include <pwd.h>

#include "knownhosts.c"

#define TORTURE_KNOWN_HOSTS_FILE "libssh_torture_knownhosts"

#define BAD_ED25519 "AAAAC3NzaC1lZDI1NTE5AAAAIE74wHmKKkrxpW/dZ69pKPlMoWG9VvWfrNnUkWRQqaDa"

static int sshd_group_setup(void **state)
{
    torture_setup_sshd_server(state, false);

    return 0;
}

static int sshd_group_teardown(void **state) {
    torture_teardown_sshd_server(state);

    return 0;
}

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_options_set(s->ssh.session,
                         SSH_OPTIONS_USER,
                         TORTURE_SSH_USER_ALICE);
    assert_ssh_return_code(s->ssh.session, rc);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;
    char known_hosts_file[1024];

    snprintf(known_hosts_file,
             sizeof(known_hosts_file),
             "%s/%s",
             s->socket_dir,
             TORTURE_KNOWN_HOSTS_FILE);

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    unlink(known_hosts_file);

    return 0;
}

#define KNOWN_HOST_ENTRY_ECDSA "127.0.0.10 ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHOg+9vHW2kJB50j7c7WkcCcOtwgZdeXMpAeEl17sFnTTrT8wYo1FCzE07wV262vIC+AE3fXUJ7sJ/CkFIdk/8/gQEY1jyoXB3Bsee16VwhJGsMzGGh1FJ0XXhRJjUbG18qbH9JiSgE1N4fIM0zJG68fAyUxRxCI1wUobOOB7EmFZd18g==\n"
#define KNOWN_HOST_ENTRY_ED25519 "127.0.0.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBWWnxuCYiOyvMYLtkgoEyEKlLV+klM+BU6Nh3PmAiqX\n"
static void torture_knownhosts_export(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char *entry = NULL;
    char *p = NULL;
    int rc;

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    rc = ssh_session_export_known_hosts_entry(session, &entry);
    assert_ssh_return_code(session, rc);

    p = strstr(entry, "ssh-ed25519");
    if (p != NULL) {
        assert_string_equal(entry, KNOWN_HOST_ENTRY_ED25519);
    } else {
        assert_string_equal(entry, KNOWN_HOST_ENTRY_ECDSA);
    }
    SAFE_FREE(entry);
}

static void torture_knownhosts_write_and_verify(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    enum ssh_known_hosts_e found;
    int rc;

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    rc = ssh_session_update_known_hosts(session);
    assert_ssh_return_code(session, rc);

    found = ssh_session_is_known_server(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);
}

static void torture_knownhosts_precheck(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    struct ssh_list *algo_list = NULL;
    struct ssh_iterator *it = NULL;
    size_t algo_count;
    const char *algo = NULL;
    char known_hosts_file[1024] = {0};
    FILE *file;
    int rc;

    snprintf(known_hosts_file,
             sizeof(known_hosts_file),
             "%s/%s",
             s->socket_dir,
             TORTURE_KNOWN_HOSTS_FILE);

    file = fopen(known_hosts_file, "w");
    assert_non_null(file);
    fprintf(file,
            "127.0.0.10 %s\n",
            torture_get_testkey_pub(SSH_KEYTYPE_RSA, 0));

    fprintf(file,
            "127.0.0.10 %s\n",
            torture_get_testkey_pub(SSH_KEYTYPE_ED25519, 0));

    fprintf(file,
            "127.0.0.10 %s\n",
            torture_get_testkey_pub(SSH_KEYTYPE_ECDSA, 521));

    fclose(file);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_ssh_return_code(session, rc);

    algo_list = ssh_known_hosts_get_algorithms(session);
    assert_non_null(algo_list);

    algo_count = ssh_list_count(algo_list);
    assert_int_equal(algo_count, 3);

    it = ssh_list_get_iterator(algo_list);
    assert_non_null(it);
    algo = ssh_iterator_value(const char *, it);
    assert_string_equal(algo, "ssh-rsa");

    ssh_list_remove(algo_list, it);

    it = ssh_list_get_iterator(algo_list);
    assert_non_null(it);
    algo = ssh_iterator_value(const char *, it);
    assert_string_equal(algo, "ssh-ed25519");

    ssh_list_remove(algo_list, it);

    it = ssh_list_get_iterator(algo_list);
    assert_non_null(it);
    algo = ssh_iterator_value(const char *, it);
    assert_string_equal(algo, "ecdsa-sha2-nistp521");

    ssh_list_free(algo_list);
}

static void torture_knownhosts_other(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char known_hosts_file[1024] = {0};
    enum ssh_known_hosts_e found;
    FILE *file = NULL;
    int rc;

    snprintf(known_hosts_file,
             sizeof(known_hosts_file),
             "%s/%s",
             s->socket_dir,
             TORTURE_KNOWN_HOSTS_FILE);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-ed25519");
    assert_ssh_return_code(session, rc);

    file = fopen(known_hosts_file, "w");
    assert_non_null(file);
    fprintf(file,
            "127.0.0.10 %s\n",
            torture_get_testkey_pub(SSH_KEYTYPE_RSA, 0));
    fclose(file);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    found = ssh_session_is_known_server(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OTHER);
}

static void torture_knownhosts_unknown(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char known_hosts_file[1024] = {0};
    enum ssh_known_hosts_e found;
    int rc;

    snprintf(known_hosts_file,
             sizeof(known_hosts_file),
             "%s/%s",
             s->socket_dir,
             TORTURE_KNOWN_HOSTS_FILE);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-ed25519");
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    found = ssh_session_is_known_server(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_UNKNOWN);

    rc = ssh_session_update_known_hosts(session);
    assert_ssh_return_code(session, rc);

    ssh_disconnect(session);
    ssh_free(session);

    /* connect again and check host key */
    session = ssh_new();
    assert_non_null(session);

    s->ssh.session = session;

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_options_set(s->ssh.session,
                         SSH_OPTIONS_USER,
                         TORTURE_SSH_USER_ALICE);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    /* ssh-rsa is the default but libssh should try ssh-ed25519 instead */
    found = ssh_session_is_known_server(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);

    /* session will be freed by session_teardown() */
}

static void torture_knownhosts_conflict(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char known_hosts_file[1024] = {0};
    enum ssh_known_hosts_e found;
    FILE *file = NULL;
    int rc;

    snprintf(known_hosts_file,
             sizeof(known_hosts_file),
             "%s/%s",
             s->socket_dir,
             TORTURE_KNOWN_HOSTS_FILE);

    file = fopen(known_hosts_file, "w");
    assert_non_null(file);
    fprintf(file,
            "127.0.0.10 %s %s\n",
            "ssh-ed25519",
            BAD_ED25519);
    fclose(file);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-ed25519");
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    found = ssh_session_is_known_server(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_CHANGED);

    rc = ssh_session_update_known_hosts(session);
    assert_ssh_return_code(session, rc);

    ssh_disconnect(session);
    ssh_free(session);

    /* connect again and check host key */
    session = ssh_new();
    assert_non_null(session);

    s->ssh.session = session;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-ed25519");
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    found = ssh_session_is_known_server(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);

    /* session will be freed by session_teardown() */
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_knownhosts_export,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_knownhosts_write_and_verify,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_knownhosts_precheck,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_knownhosts_other,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_knownhosts_unknown,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_knownhosts_conflict,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_group_setup, sshd_group_teardown);

    ssh_finalize();
    return rc;
}
