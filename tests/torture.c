#include "torture.h"

#include <stdio.h>

void torture_create_case(Suite *s, const char *name, TFun function) {
  TCase *tc_new = tcase_create(name);
  tcase_set_timeout(tc_new, 30);
  suite_add_tcase (s, tc_new);
  tcase_add_test(tc_new, function);
}

void torture_create_case_fixture(Suite *s, const char *name, TFun function, void (*setup)(void), void (*teardown)(void)) {
  TCase *tc_new = tcase_create(name);
  tcase_add_checked_fixture(tc_new, setup, teardown);
  tcase_set_timeout(tc_new, 30);
  suite_add_tcase (s, tc_new);
  tcase_add_test(tc_new, function);
}

void torture_create_case_timeout(Suite *s, const char *name, TFun function, int timeout) {
  TCase *tc_new = tcase_create(name);
  tcase_set_timeout(tc_new, timeout);
  suite_add_tcase (s, tc_new);
  tcase_add_test(tc_new, function);
}

static int verbosity=0;
int torture_libssh_verbosity(void){
  return verbosity;
}

int main(int argc, char **argv) {
  Suite *s = NULL;
  SRunner *sr = NULL;
  struct argument_s arguments;
  int nf;

  memset(&arguments,0,sizeof(struct argument_s));

  torture_cmdline_parse(argc, argv, &arguments);
  verbosity=arguments.verbose;
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
