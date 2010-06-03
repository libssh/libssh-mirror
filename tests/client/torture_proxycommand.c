#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/libssh.h>
#include "libssh/priv.h"
ssh_session session;

static void setup(void) {
    session = ssh_new();
}

static void teardown(void) {
    ssh_free(session);
}

START_TEST (torture_options_set_proxycommand)
{
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ck_assert(rc == 0);

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "nc localhost 22");
    ck_assert(rc == 0);
    rc = ssh_connect(session);
    ck_assert_msg(rc== SSH_OK,ssh_get_error(session));
}
END_TEST

START_TEST (torture_options_set_proxycommand_notexist)
{
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ck_assert(rc == 0);

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "this_command_does_not_exist");
    ck_assert(rc == SSH_OK);
    rc = ssh_connect(session);
    ck_assert_msg(rc== SSH_ERROR);
}
END_TEST

Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_proxycommand");

  torture_create_case_fixture(s, "torture_options_set_proxycommand",
          torture_options_set_proxycommand, setup, teardown);
  torture_create_case_fixture(s, "torture_options_set_proxycommand_notexist",
          torture_options_set_proxycommand_notexist, setup, teardown);


  return s;
}
