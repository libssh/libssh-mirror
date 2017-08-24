#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/options.h"

#define LIBSSH_TESTCONFIG1 "libssh_testconfig1.tmp"
#define LIBSSH_TESTCONFIG2 "libssh_testconfig2.tmp"
#define LIBSSH_TESTCONFIG3 "libssh_testconfig3.tmp"

#define USERNAME "testuser"
#define PROXYCMD "ssh -q -W %h:%p gateway.example.com"
#define ID_FILE "/etc/xxx"

static int setup_config_files(void **state)
{
    ssh_session session;

    unlink(LIBSSH_TESTCONFIG1);
    unlink(LIBSSH_TESTCONFIG2);
    unlink(LIBSSH_TESTCONFIG3);

    torture_write_file(LIBSSH_TESTCONFIG1,
                       "User "USERNAME"\nInclude "LIBSSH_TESTCONFIG2"\n\n");
    torture_write_file(LIBSSH_TESTCONFIG2,
                       "Include "LIBSSH_TESTCONFIG3"\n"
                       "ProxyCommand "PROXYCMD"\n\n");
    torture_write_file(LIBSSH_TESTCONFIG3,
                       "\n\nIdentityFile "ID_FILE"\n");

    session = ssh_new();
    *state = session;

    return 0;
}

static int teardown(void **state)
{
    unlink(LIBSSH_TESTCONFIG1);
    unlink(LIBSSH_TESTCONFIG2);
    unlink(LIBSSH_TESTCONFIG3);

    ssh_free(*state);

    return 0;
}


/**
 * @brief tests the privatekey_from_file function with passphrase
 */
static void torture_config_from_file(void **state) {
    ssh_session session = *state;
    int ret;
    char *v;

    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG1);
    assert_true(ret == 0);

    /* Test the variable presence */

    ret = ssh_options_get(session, SSH_OPTIONS_PROXYCOMMAND, &v);
    assert_true(ret == 0);

    assert_string_equal(v, PROXYCMD);
    ssh_string_free_char(v);

    ret = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &v);
    assert_true(ret == 0);

    assert_string_equal(v, ID_FILE);
    ssh_string_free_char(v);

    ret = ssh_options_get(session, SSH_OPTIONS_USER, &v);
    assert_true(ret == 0);

    assert_string_equal(v, USERNAME);
    ssh_string_free_char(v);

}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_config_from_file,
                                        setup_config_files,
                                        teardown),
    };


    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
