/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

#define LIBSSH_STATIC

#include "torture.h"
#include "session.c"

#define KNOWNHOSTFILES "libssh_torture_knownhosts"

static void setup(void **state) {
    int verbosity=torture_libssh_verbosity();
    ssh_session session = ssh_new();

    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    *state = session;
}

static void teardown(void **state) {
    ssh_session session = *state;

    ssh_disconnect(session);
    ssh_free(session);

    unlink(KNOWNHOSTFILES);
}

static void torture_knownhosts_port(void **state) {
    ssh_session session = *state;
    char buffer[200];
    char *p;
    FILE *file;
    int rc;

    /* Connect to localhost:22, force the port to 1234 and then write
     * the known hosts file. Then check that the entry written is
     * [localhost]:1234
     */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    session->opts.port = 1234;
    rc = ssh_write_knownhost(session);
    assert_true(rc == SSH_OK);

    file = fopen(KNOWNHOSTFILES, "r");
    assert_true(file != NULL);
    p = fgets(buffer, sizeof(buffer), file);
    assert_false(p == NULL);
    fclose(file);
    buffer[sizeof(buffer) - 1] = '\0';
    assert_true(strstr(buffer,"[localhost]:1234 ") != NULL);

    ssh_disconnect(session);
    ssh_free(session);

    /* Now, connect back to the ssh server and verify the known host line */
    *state = session = ssh_new();

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);

    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);

    session->opts.port = 1234;
    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_KNOWN_OK);
}

static void torture_knownhosts_fail(void **state) {
    ssh_session session = *state;
    FILE *file;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
    assert_true(rc == SSH_OK);

    file = fopen(KNOWNHOSTFILES, "w");
    assert_true(file != NULL);
    fprintf(file, "localhost ssh-rsa %s\n", BADRSA);
    fclose(file);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_KNOWN_CHANGED);
}

static void torture_knownhosts_other(void **state) {
    ssh_session session = *state;
    FILE *file;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-dss");
    assert_true(rc == SSH_OK);

    file = fopen(KNOWNHOSTFILES, "w");
    assert_true(file != NULL);
    fprintf(file, "localhost ssh-rsa %s\n", BADRSA);
    fclose(file);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_FOUND_OTHER);
}

static void torture_knownhosts_other_auto(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-dss");
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_NOT_KNOWN);

    rc = ssh_write_knownhost(session);
    assert_true(rc == SSH_OK);

    ssh_disconnect(session);
    ssh_free(session);

    /* connect again and check host key */
    *state = session = ssh_new();

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    /* ssh-rsa is the default but libssh should try ssh-dss instead */
    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_KNOWN_OK);
}

static void torture_knownhosts_conflict(void **state) {
    ssh_session session = *state;
    FILE *file;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
    assert_true(rc == SSH_OK);

    file = fopen(KNOWNHOSTFILES, "w");
    assert_true(file != NULL);
    fprintf(file, "localhost ssh-rsa %s\n", BADRSA);
    fprintf(file, "localhost ssh-dss %s\n", BADDSA);
    fclose(file);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_KNOWN_CHANGED);

    rc = ssh_write_knownhost(session);
    assert_true(rc==SSH_OK);

    ssh_disconnect(session);
    ssh_free(session);

    /* connect again and check host key */
    *state = session = ssh_new();

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);

    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_KNOWN_OK);
}

static void torture_knownhosts_precheck(void **state) {
    ssh_session session = *state;
    FILE *file;
    int rc;
    int dsa;
    int rsa;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    file = fopen(KNOWNHOSTFILES, "w");
    assert_true(file != NULL);
    fprintf(file, "localhost ssh-rsa %s\n", BADRSA);
    fprintf(file, "localhost ssh-dss %s\n", BADDSA);
    fclose(file);

    rc = ssh_knownhosts_algorithms(session);
    assert_true(rc != SSH_ERROR);
    dsa = 1 << SSH_KEYTYPE_DSS;
    rsa = 1 << SSH_KEYTYPE_RSA;
    assert_true(rc & dsa);
    assert_true(rc & rsa);
    /* nothing else than dsa and rsa */
    assert_true((rc & (dsa | rsa)) == rc);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_knownhosts_port, setup, teardown),
        unit_test_setup_teardown(torture_knownhosts_fail, setup, teardown),
        unit_test_setup_teardown(torture_knownhosts_other, setup, teardown),
        unit_test_setup_teardown(torture_knownhosts_other_auto, setup, teardown),
        unit_test_setup_teardown(torture_knownhosts_conflict, setup, teardown),
        unit_test_setup_teardown(torture_knownhosts_precheck, setup, teardown)
    };

    ssh_init();

    rc = run_tests(tests);

    ssh_finalize();
    return rc;
}
