#include <sys/types.h>
#include <pwd.h>

#define LIBSSH_STATIC
#include <libssh/priv.h>

#include "torture.h"
#include "misc.c"

START_TEST (torture_get_user_home_dir)
{
    struct passwd *pwd;
    char *user;

    pwd = getpwuid(getuid());

    user = ssh_get_user_home_dir();
    ck_assert_str_eq(user, pwd->pw_dir);

    SAFE_FREE(user);
}
END_TEST

static Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_misc");

  torture_create_case(s, "torture_get_user_home_dir", torture_get_user_home_dir);

  return s;
}

int main(int argc, char **argv) {
  Suite *s = NULL;
  SRunner *sr = NULL;
  struct argument_s arguments;
  int nf;

  ZERO_STRUCT(arguments);

  torture_cmdline_parse(argc, argv, &arguments);

  s = torture_make_suite();

  sr = srunner_create(s);
  if (arguments.nofork) {
    srunner_set_fork_status(sr, CK_NOFORK);
  }
  srunner_run_all(sr, CK_VERBOSE);
  nf = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

