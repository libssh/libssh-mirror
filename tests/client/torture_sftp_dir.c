#define LIBSSH_STATIC

#include "torture.h"
#include "sftp.c"

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
    ssh_session session;
    struct torture_sftp *t;
    struct passwd *pwd;

    pwd = getpwnam("bob");
    assert_non_null(pwd);
    setuid(pwd->pw_uid);

    session = torture_ssh_session(TORTURE_SSH_SERVER,
                                  NULL,
                                  TORTURE_SSH_USER_ALICE,
                                  NULL);
    assert_false(session == NULL);
    t = torture_sftp_session(session);
    assert_false(t == NULL);

    *state = t;
}

static void teardown(void **state) {
    struct torture_sftp *t = *state;

    assert_false(t == NULL);

    torture_rmdirs(t->testdir);
    torture_sftp_close(t);
}

static void torture_sftp_mkdir(void **state) {
    struct torture_sftp *t = *state;
    char tmpdir[128] = {0};
    int rc;

    assert_false(t == NULL);

    snprintf(tmpdir, sizeof(tmpdir) - 1, "%s/mkdir_test", t->testdir);

    rc = sftp_mkdir(t->sftp, tmpdir, 0755);
    if(rc != SSH_OK)
        fprintf(stderr,"error:%s\n",ssh_get_error(t->sftp->session));
    assert_true(rc == 0);

    /* check if it really has been created */
    assert_true(torture_isdir(tmpdir));

    rc = sftp_rmdir(t->sftp, tmpdir);
    assert_true(rc == 0);

    /* check if it has been deleted */
    assert_false(torture_isdir(tmpdir));
}

int torture_run_tests(void) {
    int rc;
    struct torture_state *s = NULL;
    UnitTest tests[] = {
        unit_test_setup_teardown(torture_sftp_mkdir, setup, teardown)
    };

    ssh_init();

    torture_filter_tests(tests);
    sshd_setup((void **)&s);
    rc = run_tests(tests);
    sshd_teardown((void **)&s);
    ssh_finalize();

    return rc;
}
