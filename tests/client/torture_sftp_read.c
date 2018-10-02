#define LIBSSH_STATIC

#include "torture.h"
#include "sftp.c"

#include <sys/types.h>
#include <pwd.h>

#define MAX_XFER_BUF_SIZE 16384

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
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

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
    struct torture_sftp *t = (struct torture_sftp*) *state;

    assert_false(t == NULL);

    torture_rmdirs(t->testdir);
    torture_sftp_close(t);
}

static void torture_sftp_read_blocking(void **state) {
    struct torture_sftp *t = (struct torture_sftp*) *state;
    char libssh_tmp_file[] = "/tmp/libssh_sftp_test_XXXXXX";
    char buf[MAX_XFER_BUF_SIZE];
    ssize_t bytesread;
    ssize_t byteswritten;
    int fd;
    sftp_file file;
    mode_t mask;

    file = sftp_open(t->sftp, "/usr/bin/ssh", O_RDONLY, 0);
    assert_non_null(file);

    mask = umask(S_IRWXO | S_IRWXG);
    fd = mkstemp(libssh_tmp_file);
    umask(mask);
    unlink(libssh_tmp_file);

    for (;;) {
        bytesread = sftp_read(file, buf, MAX_XFER_BUF_SIZE);
        if (bytesread == 0) {
                break; /* EOF */
        }
        assert_false(bytesread < 0);

        byteswritten = write(fd, buf, bytesread);
        assert_int_equal(byteswritten, bytesread);
    }

    close(fd);
    sftp_close(file);
}

int torture_run_tests(void) {
    int rc;
    struct torture_state *s = NULL;
    UnitTest tests[] = {
        unit_test_setup_teardown(torture_sftp_read_blocking, setup, teardown)
    };

    ssh_init();

    torture_filter_tests(tests);
    sshd_setup((void **)&s);
    rc = run_tests(tests);
    sshd_teardown((void **)&s);
    ssh_finalize();

    return rc;
}
