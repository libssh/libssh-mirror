#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/libssh.h>
#include "libssh/priv.h"

#include <errno.h>
#include <sys/types.h>
#include <pwd.h>

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state);

    return 0;
}

static int sshd_teardown(void **state) {
    torture_teardown_sshd_server(state);

    return 0;
}

static void setup(void **state) {
    ssh_session session = ssh_new();
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);

    ssh_options_set(session, SSH_OPTIONS_USER, TORTURE_SSH_USER_ALICE);

    *state = session;
}

static void teardown(void **state) {
    ssh_free(*state);
}

static void torture_options_set_proxycommand(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "nc 127.0.0.10 22");
    assert_true(rc == 0);
    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);
}

static void torture_options_set_proxycommand_notexist(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "this_command_does_not_exist");
    assert_true(rc == SSH_OK);
    rc = ssh_connect(session);
    assert_true(rc == SSH_ERROR);
}

int torture_run_tests(void) {
    int rc;
    struct torture_state *s = NULL;
    UnitTest tests[] = {
        unit_test_setup_teardown(torture_options_set_proxycommand, setup, teardown),
        unit_test_setup_teardown(torture_options_set_proxycommand_notexist, setup, teardown),
    };


    ssh_init();

    torture_filter_tests(tests);
    sshd_setup((void **)&s);
    rc = run_tests(tests);
    sshd_teardown((void **)&s);
    ssh_finalize();

    return rc;
}
