#define LIBSSH_STATIC
#include <libssh/libssh.h>
#include "libssh/priv.h"
#include "torture.h"

START_TEST (torture_ssh_init)
{
    int rc;
    rc=ssh_init();
    ck_assert_int_eq(rc,SSH_OK);
    rc=ssh_finalize();
    ck_assert_int_eq(rc,SSH_OK);
}
END_TEST

static Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_init");

  torture_create_case(s, "torture_ssh_init", torture_ssh_init);

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

