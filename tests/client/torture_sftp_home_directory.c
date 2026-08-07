#include "config.h"

#define LIBSSH_STATIC

#include "sftp.c"
#include "torture.h"

#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>

static int
sshd_setup(void **state)
{
    /*
      The SFTP server used for testing is executed as a separate binary, which
      is making the uid_wrapper lose information about what user is used, and
      therefore, pwd is initialized to some bad value.
      If the embedded version using internal-sftp is used in sshd, it works ok.
     */
    setenv("TORTURE_SFTP_SERVER", "internal-sftp", 1);
    torture_setup_sshd_server(state, false);
    return 0;
}

static int
sshd_teardown(void **state)
{
    unsetenv("TORTURE_SFTP_SERVER");
    torture_teardown_sshd_server(state);
    return 0;
}

static int
session_setup(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd = NULL;
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

    return 0;
}

static int
session_teardown(void **state)
{
    struct torture_state *s = *state;

    torture_rmdirs(s->ssh.tsftp->testdir);
    torture_sftp_close(s->ssh.tsftp);
    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void
torture_sftp_home_directory(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;
    struct passwd *pwd = NULL;
    char *home_path = NULL;
    int rc;

    rc = sftp_extension_supported(t->sftp, "home-directory", "1");
    if (!rc) {
        skip();
    }

    pwd = getpwnam(TORTURE_SSH_USER_ALICE);
    assert_non_null(pwd);

    /* testing for NULL sftp session */
    home_path = sftp_home_directory(NULL, NULL);
    assert_null(home_path);

    /* testing for ~ */
    /*
    home_path = sftp_home_directory(t->sftp, NULL);
    assert_non_null(home_path);
    assert_string_equal(home_path, pwd->pw_dir);
    SSH_STRING_FREE_CHAR(home_path);

    home_path = sftp_home_directory(t->sftp, "");
    assert_non_null(home_path);
    assert_string_equal(home_path, pwd->pw_dir);
    SSH_STRING_FREE_CHAR(home_path);
    */

    /*
      OpenSSH code handling this extension does not handle empty string for
      username. getpwnam() also does not handle empty string.
      PR in OpenSSH for fix:
      https://github.com/openssh/openssh-portable/pull/477/
    */

    /* testing for ~user */
    home_path = sftp_home_directory(t->sftp, pwd->pw_name);
    fprintf(stderr,
            "sftp error: %d, ssh error: %s\n",
            sftp_get_error(t->sftp),
            ssh_get_error(t->sftp->session));
    assert_non_null(home_path);
    assert_string_equal(home_path, pwd->pw_dir);
    SSH_STRING_FREE_CHAR(home_path);
}

/* A missing-path NAME reply should fail without leaking the reply message. */
static void torture_sftp_home_directory_missing_path(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;
    sftp_session sftp = t->sftp;
    ssh_buffer payload = NULL;
    char *home_path = NULL;
    int rc;

    payload = ssh_buffer_new();
    assert_non_null(payload);

    /* Replies are matched by id. The next request will use id_counter + 1. */
    rc = ssh_buffer_pack(payload,
                         "dd",
                         sftp->id_counter + 1, /* request id */
                         (uint32_t)1);         /* count; no path */
    assert_int_equal(rc, SSH_OK);

    rc = torture_sftp_feed_packet(sftp, SSH_FXP_NAME, payload);
    assert_int_equal(rc, SSH_OK);
    SSH_BUFFER_FREE(payload);

    /* The request adds an id to this list, and a matching reply removes it. */
    assert_int_equal(ssh_list_count(sftp->outstanding_ids), 0);

    home_path = sftp_home_directory(sftp, TORTURE_SSH_USER_ALICE);
    assert_null(home_path);
    assert_int_equal(sftp_get_error(sftp), SSH_FX_FAILURE);

    assert_int_equal(ssh_list_count(sftp->outstanding_ids), 0);
}

/* A truncated-attributes NAME reply should fail without leaking the reply
 * message, path or longname. */
static void torture_sftp_home_directory_truncated_attributes(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;
    sftp_session sftp = t->sftp;
    ssh_buffer payload = NULL;
    char *home_path = NULL;
    int rc;

    payload = ssh_buffer_new();
    assert_non_null(payload);

    /* Replies are matched by id. The next request will use id_counter + 1. */
    rc = ssh_buffer_pack(payload,
                         "dds",
                         sftp->id_counter + 1, /* request id */
                         (uint32_t)1,          /* count */
                         "/home/victim");      /* path */
    assert_int_equal(rc, SSH_OK);

    /* A longname field follows the path only through version 3. */
    if (sftp->version <= 3) {
        rc = ssh_buffer_pack(payload, "s", "drwxr-xr-x  home"); /* longname */
        assert_int_equal(rc, SSH_OK);
    }

    /* The size flag promises a field that is not appended. */
    rc = ssh_buffer_pack(payload, "d", (uint32_t)SSH_FILEXFER_ATTR_SIZE);
    assert_int_equal(rc, SSH_OK);

    rc = torture_sftp_feed_packet(sftp, SSH_FXP_NAME, payload);
    assert_int_equal(rc, SSH_OK);
    SSH_BUFFER_FREE(payload);

    /* The request adds an id to this list, and a matching reply removes it. */
    assert_int_equal(ssh_list_count(sftp->outstanding_ids), 0);

    home_path = sftp_home_directory(sftp, TORTURE_SSH_USER_ALICE);
    assert_null(home_path);
    assert_int_equal(ssh_get_error_code(sftp->session), SSH_FATAL);

    assert_int_equal(ssh_list_count(sftp->outstanding_ids), 0);
}

/* A bad-count NAME reply should fail without leaking the reply message, path,
 * longname or attributes. */
static void torture_sftp_home_directory_bad_count(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;
    sftp_session sftp = t->sftp;
    ssh_buffer payload = NULL;
    char *home_path = NULL;
    int rc;

    payload = ssh_buffer_new();
    assert_non_null(payload);

    /* Replies are matched by id. The next request will use id_counter + 1. */
    rc = ssh_buffer_pack(payload,
                         "dds",
                         sftp->id_counter + 1, /* request id */
                         (uint32_t)2,          /* count; one name follows */
                         "/home/victim");      /* path */
    assert_int_equal(rc, SSH_OK);

    /* A longname field follows the path only through version 3. */
    if (sftp->version <= 3) {
        rc = ssh_buffer_pack(payload, "s", "drwxr-xr-x  home"); /* longname */
        assert_int_equal(rc, SSH_OK);
    }

    /* count is checked after the attributes are parsed. */
    rc = ssh_buffer_pack(payload, "d", (uint32_t)0); /* attribute flags */
    assert_int_equal(rc, SSH_OK);

    rc = torture_sftp_feed_packet(sftp, SSH_FXP_NAME, payload);
    assert_int_equal(rc, SSH_OK);
    SSH_BUFFER_FREE(payload);

    /* The request adds an id to this list, and a matching reply removes it. */
    assert_int_equal(ssh_list_count(sftp->outstanding_ids), 0);

    home_path = sftp_home_directory(sftp, TORTURE_SSH_USER_ALICE);
    assert_null(home_path);
    assert_int_equal(sftp_get_error(sftp), SSH_FX_FAILURE);
    assert_int_equal(ssh_get_error_code(sftp->session), SSH_ERROR);

    assert_int_equal(ssh_list_count(sftp->outstanding_ids), 0);
}

/* An error STATUS reply should fail without leaking the reply message or the
 * status message. */
static void torture_sftp_home_directory_error_status(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;
    sftp_session sftp = t->sftp;
    ssh_buffer payload = NULL;
    char *home_path = NULL;
    int rc;

    payload = ssh_buffer_new();
    assert_non_null(payload);

    /* Replies are matched by id. The next request will use id_counter + 1. */
    rc = ssh_buffer_pack(payload,
                         "ddss",
                         sftp->id_counter + 1,               /* request id */
                         (uint32_t)SSH_FX_PERMISSION_DENIED, /* status */
                         "permission denied",                /* message */
                         "en");                              /* language tag */
    assert_int_equal(rc, SSH_OK);

    rc = torture_sftp_feed_packet(sftp, SSH_FXP_STATUS, payload);
    assert_int_equal(rc, SSH_OK);
    SSH_BUFFER_FREE(payload);

    /* The request adds an id to this list, and a matching reply removes it. */
    assert_int_equal(ssh_list_count(sftp->outstanding_ids), 0);

    home_path = sftp_home_directory(sftp, TORTURE_SSH_USER_ALICE);
    assert_null(home_path);
    assert_int_equal(sftp_get_error(sftp), SSH_FX_PERMISSION_DENIED);

    assert_int_equal(ssh_list_count(sftp->outstanding_ids), 0);
}

int
torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_sftp_home_directory,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(
            torture_sftp_home_directory_missing_path,
            session_setup,
            session_teardown),
        cmocka_unit_test_setup_teardown(
            torture_sftp_home_directory_truncated_attributes,
            session_setup,
            session_teardown),
        cmocka_unit_test_setup_teardown(torture_sftp_home_directory_bad_count,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(
            torture_sftp_home_directory_error_status,
            session_setup,
            session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
