#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "sftp.c"

#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state, false);

    return 0;
}

static int sshd_teardown(void **state) {
    torture_teardown_sshd_server(state);

    return 0;
}

static void session_setup(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = torture_ssh_session(s,
                                         TORTURE_SSH_SERVER,
                                         NULL,
                                         TORTURE_SSH_USER_ALICE,
                                         NULL);
    assert_non_null(s->ssh.session);

    s->ssh.tsftp = torture_sftp_session(s->ssh.session);
    assert_non_null(s->ssh.tsftp);
}

static void session_setup_channel(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd = NULL;
    ssh_channel c = NULL;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = torture_ssh_session(s,
                                         TORTURE_SSH_SERVER,
                                         NULL,
                                         TORTURE_SSH_USER_ALICE,
                                         NULL);
    assert_non_null(s->ssh.session);

    c = ssh_channel_new(s->ssh.session);
    assert_non_null(c);

    s->ssh.tsftp = torture_sftp_session_channel(s->ssh.session, c);
    assert_non_null(s->ssh.tsftp);
}

static void session_setup_extensions(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd = NULL;
    int rc, count;
    const char *name = NULL, *data = NULL;
    sftp_session sftp = NULL;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = torture_ssh_session(s,
                                         TORTURE_SSH_SERVER,
                                         NULL,
                                         TORTURE_SSH_USER_ALICE,
                                         NULL);
    assert_non_null(s->ssh.session);

    s->ssh.tsftp = torture_sftp_session(s->ssh.session);
    assert_non_null(s->ssh.tsftp);
    sftp = s->ssh.tsftp->sftp;

    /* null parameter */
    count = sftp_extensions_get_count(NULL);
    assert_int_equal(count, 0);

    count = sftp_extensions_get_count(sftp);
    assert_int_not_equal(count, 0);

    /* first null parameter */
    name = sftp_extensions_get_name(NULL, 0);
    assert_null(name);
    data = sftp_extensions_get_data(NULL, 0);
    assert_null(data);

    /* First extension */
    name = sftp_extensions_get_name(sftp, 0);
    assert_non_null(name);
    data = sftp_extensions_get_data(sftp, 0);
    assert_non_null(data);

    /* Last extension */
    name = sftp_extensions_get_name(sftp, count - 1);
    assert_non_null(name);
    data = sftp_extensions_get_data(sftp, count - 1);
    assert_non_null(data);

    /* Overrun */
    name = sftp_extensions_get_name(sftp, count);
    assert_null(name);
    data = sftp_extensions_get_data(sftp, count);
    assert_null(data);
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    torture_rmdirs(s->ssh.tsftp->testdir);
    torture_sftp_close(s->ssh.tsftp);
    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

/* A truncated VERSION reply should succeed without leaking the extension
 * name. */
static void torture_sftp_init_truncated_extension(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = NULL;
    struct passwd *pwd = NULL;
    char template[] = "/tmp/ssh_torture_XXXXXX";
    char *p = NULL;
    sftp_session sftp = NULL;
    ssh_buffer payload = NULL;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = torture_ssh_session(s,
                                         TORTURE_SSH_SERVER,
                                         NULL,
                                         TORTURE_SSH_USER_ALICE,
                                         NULL);
    assert_non_null(s->ssh.session);

    /* Set up torture_sftp manually so the fabricated packet can be buffered
     * before sftp_init() runs. */
    t = calloc(1, sizeof(struct torture_sftp));
    assert_non_null(t);
    s->ssh.tsftp = t;

    p = mkdtemp(template);
    assert_non_null(p);
    t->testdir = strdup(p); /* unused, required by session_teardown() */
    assert_non_null(t->testdir);

    t->sftp = sftp_new(s->ssh.session);
    assert_non_null(t->sftp);
    sftp = t->sftp;

    payload = ssh_buffer_new();
    assert_non_null(payload);

    rc = ssh_buffer_pack(payload,
                         "dsss",
                         (uint32_t)LIBSFTP_VERSION,
                         "complete@example.com",   /* name 1 */
                         "7",                      /* value 1 */
                         "truncated@example.com"); /* name 2, no value */
    assert_int_equal(rc, SSH_OK);

    rc = torture_sftp_feed_packet(sftp, SSH_FXP_VERSION, payload);
    assert_int_equal(rc, SSH_OK);

    SSH_BUFFER_FREE(payload);

    rc = sftp_init(sftp);
    assert_int_equal(rc, SSH_OK);

    /* The complete pair registered, but the truncated one did not. */
    assert_int_equal(sftp_extensions_get_count(sftp), 1);
    assert_string_equal(sftp_extensions_get_name(sftp, 0),
                        "complete@example.com");
    assert_string_equal(sftp_extensions_get_data(sftp, 0), "7");
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(session_setup,
                                        NULL,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(session_setup_channel,
                                        NULL,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(session_setup_extensions,
                                        NULL,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_sftp_init_truncated_extension,
                                        NULL,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();

    return rc;
}
