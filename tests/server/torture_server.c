/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Red Hat, Inc.
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

#define LIBSSH_STATIC

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>

#include "torture.h"
#include "torture_key.h"
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"

#include "test_server.h"
#include "default_cb.h"

struct test_server_st {
    struct torture_state *state;
    struct server_state_st *ss;
};

static int setup_default_server(void **state)
{
    struct torture_state *s;
    struct server_state_st *ss;
    struct test_server_st *tss;
#ifdef HAVE_DSA
    char dsa_hostkey[1024];
#endif /* HAVE_DSA */

    char ed25519_hostkey[1024] = {0};
    char rsa_hostkey[1024];
    char ecdsa_hostkey[1024];
    //char trusted_ca_pubkey[1024];

    char sshd_path[1024];
    struct stat sb;

    const char *sftp_server_locations[] = {
        "/usr/lib/ssh/sftp-server",
        "/usr/libexec/sftp-server",
        "/usr/libexec/openssh/sftp-server",
        "/usr/lib/openssh/sftp-server",     /* Debian */
    };

    size_t sftp_sl_size = ARRAY_SIZE(sftp_server_locations);
    const char *sftp_server;

    size_t i;
    int rc;

    char pid_str[1024];

    pid_t pid;

    assert_non_null(state);

    tss = (struct test_server_st*)malloc(sizeof(struct test_server_st));
    assert_non_null(tss);

    torture_setup_socket_dir((void **)&s);
    assert_non_null(s->socket_dir);

    /* Set the default interface for the server */
    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "10", 1);
    setenv("PAM_WRAPPER", "1", 1);

    snprintf(sshd_path,
             sizeof(sshd_path),
             "%s/sshd",
             s->socket_dir);

    rc = mkdir(sshd_path, 0755);
    assert_return_code(rc, errno);

    snprintf(ed25519_hostkey,
             sizeof(ed25519_hostkey),
             "%s/sshd/ssh_host_ed25519_key",
             s->socket_dir);
    torture_write_file(ed25519_hostkey,
                       torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 0, 0));

#ifdef HAVE_DSA
    snprintf(dsa_hostkey,
             sizeof(dsa_hostkey),
             "%s/sshd/ssh_host_dsa_key",
             s->socket_dir);
    torture_write_file(dsa_hostkey, torture_get_testkey(SSH_KEYTYPE_DSS, 0, 0));
#endif /* HAVE_DSA */

    snprintf(rsa_hostkey,
             sizeof(rsa_hostkey),
             "%s/sshd/ssh_host_rsa_key",
             s->socket_dir);
    torture_write_file(rsa_hostkey, torture_get_testkey(SSH_KEYTYPE_RSA, 0, 0));

    snprintf(ecdsa_hostkey,
             sizeof(ecdsa_hostkey),
             "%s/sshd/ssh_host_ecdsa_key",
             s->socket_dir);
    torture_write_file(ecdsa_hostkey,
                       torture_get_testkey(SSH_KEYTYPE_ECDSA, 521, 0));

    sftp_server = getenv("TORTURE_SFTP_SERVER");
    if (sftp_server == NULL) {
        for (i = 0; i < sftp_sl_size; i++) {
            sftp_server = sftp_server_locations[i];
            rc = lstat(sftp_server, &sb);
            if (rc == 0) {
                break;
            }
        }
    }
    assert_non_null(sftp_server);

    /* Create default server state */
    ss = (struct server_state_st *)malloc(sizeof(struct server_state_st));
    assert_non_null(ss);

    ss->address = strdup("127.0.0.10");
    assert_non_null(ss->address);

    ss->port = 22;

    ss->ecdsa_key = strdup(ecdsa_hostkey);
    assert_non_null(ss->ecdsa_key);

#ifdef HAVE_DSA
    ss->dsa_key = strdup(dsa_hostkey);
    assert_non_null(ss->dsa_key);
#endif /* HAVE_DSA */

    ss->ed25519_key = strdup(ed25519_hostkey);
    assert_non_null(ed25519_hostkey);

    ss->rsa_key = strdup(rsa_hostkey);
    assert_non_null(ss->rsa_key);

    ss->host_key = NULL;

    /* Use default username and password (set in default_handle_session_cb) */
    ss->expected_username = NULL;
    ss->expected_password = NULL;

    ss->verbosity = torture_libssh_verbosity();

    ss->auth_methods = SSH_AUTH_METHOD_PASSWORD;

#ifdef WITH_PCAP
    ss->with_pcap = 1;
    ss->pcap_file = strdup(s->pcap_file);
    assert_non_null(ss->pcap_file);
#endif

    /* TODO make configurable */
    ss->max_tries = 3;
    ss->error = 0;

    /* Use the default session handling function */
    ss->handle_session = default_handle_session_cb;
    assert_non_null(ss->handle_session);

    /* Start the server using the default values */
    pid = fork_run_server(ss);
    if (pid < 0) {
        fail();
    }

    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    torture_write_file(s->srv_pidfile, (const char *)pid_str);

    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "21", 1);
    unsetenv("PAM_WRAPPER");

    /* Wait until the sshd is ready to accept connections */
    //rc = torture_wait_for_daemon(5);
    //assert_int_equal(rc, 0);

    /* TODO properly wait for the server (use ping approach) */
    /* Wait 200ms */
    usleep(200 * 1000);

    tss->state = s;
    tss->ss = ss;

    *state = tss;

    return 0;
}

static int teardown_default_server(void **state)
{
    struct torture_state *s;
    struct server_state_st *ss;
    struct test_server_st *tss;

    tss = *state;
    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    ss = tss->ss;
    assert_non_null(ss);

    /* This function can be reused */
    torture_teardown_sshd_server((void **)&s);

    free_server_state(tss->ss);
    SAFE_FREE(tss->ss);
    SAFE_FREE(tss);

    return 0;
}

static int session_setup(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;
    bool b = false;
    int rc;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    /* Make sure no other configuration options from system will get used */
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_PROCESS_CONFIG, &b);
    assert_ssh_return_code(s->ssh.session, rc);

    return 0;
}

static int session_teardown(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_server_auth_password(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;
    ssh_session session;
    int rc;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    session = s->ssh.session;
    assert_non_null(session);

    /* TODO: implement proper pam authentication function */
    /* Using the default user for the server */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_none(session, NULL);
    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_AUTH_ERROR) {
        assert_int_equal(ssh_get_error_code(session), SSH_REQUEST_DENIED);
    }
    rc = ssh_userauth_list(session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_PASSWORD);

    /* TODO: implement proper pam authentication function */
    /* Using the default password for the server */
    rc = ssh_userauth_password(session, NULL, SSHD_DEFAULT_PASSWORD);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_server_auth_password,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests,
            setup_default_server,
            teardown_default_server);

    ssh_finalize();

    return rc;
}
