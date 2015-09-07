#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/libssh.h>
#include "libssh/priv.h"

static int setup(void **state) {
    ssh_session session = ssh_new();

    *state = session;

    return 0;
}

static int teardown(void **state) {
    ssh_free(*state);

    return 0;
}

static void torture_options_set_proxycommand(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == 0);

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "nc localhost 22");
    assert_true(rc == 0);
    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);
}

static void torture_options_set_proxycommand_notexist(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == 0);

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "this_command_does_not_exist");
    assert_true(rc == SSH_OK);
    rc = ssh_connect(session);
    assert_true(rc == SSH_ERROR);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_options_set_proxycommand, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_proxycommand_notexist, setup, teardown),
    };


    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}
