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
#include "libssh/libssh.h"
#include "libssh/priv.h"


static void setup(void **state) {
    ssh_session session = ssh_new();
    *state = session;
}

static void teardown(void **state) {
    ssh_free(*state);
}

static void test_algorithm(ssh_session session, const char *algo) {
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, algo);
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, algo);
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);

    rc = ssh_userauth_none(session, NULL);
    if (rc != SSH_OK) {
        rc = ssh_get_error_code(session);
        assert_true(rc == SSH_REQUEST_DENIED);
    }

    ssh_disconnect(session);
}

static void torture_algorithms_aes128_cbc(void **state) {
    test_algorithm(*state, "aes128-cbc");
}

static void torture_algorithms_aes192_cbc(void **state) {
    test_algorithm(*state, "aes192-cbc");
}

static void torture_algorithms_aes256_cbc(void **state) {
    test_algorithm(*state, "aes256-cbc");
}

static void torture_algorithms_aes128_ctr(void **state) {
    test_algorithm(*state, "aes128-ctr");
}

static void torture_algorithms_aes192_ctr(void **state) {
    test_algorithm(*state, "aes192-ctr");
}

static void torture_algorithms_aes256_ctr(void **state) {
    test_algorithm(*state, "aes256-ctr");
}

static void torture_algorithms_3des_cbc(void **state) {
    test_algorithm(*state, "3des-cbc");
}

static void torture_algorithms_blowfish_cbc(void **state) {
    test_algorithm(*state, "blowfish-cbc");
}

static void torture_algorithms_zlib(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session,SSH_OPTIONS_HOST,"localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_C_S, "zlib");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, "zlib");
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    if (ssh_get_openssh_version(session)) {
        assert_false(rc == SSH_OK);
    } else {
        assert_true(rc == SSH_OK);

        rc = ssh_userauth_none(session, NULL);
        if (rc != SSH_OK) {
            rc = ssh_get_error_code(session);
            assert_true(rc == SSH_REQUEST_DENIED);
        }
    }

    ssh_disconnect(session);
}

static void torture_algorithms_zlib_openssh(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session,SSH_OPTIONS_HOST,"localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_C_S, "zlib@openssh.com");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, "zlib@openssh.com");
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    if (ssh_get_openssh_version(session)) {
        assert_true(rc==SSH_OK);
        rc = ssh_userauth_none(session, NULL);
        if (rc != SSH_OK) {
            rc = ssh_get_error_code(session);
            assert_true(rc == SSH_REQUEST_DENIED);
        }
    } else {
      assert_false(rc == SSH_OK);
    }

    ssh_disconnect(session);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_algorithms_aes128_cbc, setup, teardown),
        unit_test_setup_teardown(torture_algorithms_aes192_cbc, setup, teardown),
        unit_test_setup_teardown(torture_algorithms_aes256_cbc, setup, teardown),
        unit_test_setup_teardown(torture_algorithms_aes128_ctr, setup, teardown),
        unit_test_setup_teardown(torture_algorithms_aes192_ctr, setup, teardown),
        unit_test_setup_teardown(torture_algorithms_aes256_ctr, setup, teardown),
        unit_test_setup_teardown(torture_algorithms_3des_cbc, setup, teardown),
        unit_test_setup_teardown(torture_algorithms_blowfish_cbc, setup, teardown),
        unit_test_setup_teardown(torture_algorithms_zlib, setup, teardown),
        unit_test_setup_teardown(torture_algorithms_zlib_openssh, setup, teardown),
    };

    ssh_init();

    rc = run_tests(tests);
    ssh_finalize();

    return rc;
}
