#define LIBSSH_STATIC
#include <libssh/priv.h>

#include "torture.h"
#include "misc.c"

START_TEST(torture_ssh_list_new)
{
    struct ssh_list *xlist;

    xlist = ssh_list_new();

    ck_assert(xlist != NULL);
    ck_assert(xlist->root == NULL);
    ck_assert(xlist->end == NULL);

    ssh_list_free(xlist);
}
END_TEST

START_TEST(torture_ssh_list_append)
{
    struct ssh_list *xlist;
    int rc;

    xlist = ssh_list_new();
    ck_assert(xlist != NULL);

    rc = ssh_list_append(xlist, "item1");
    ck_assert(rc == 0);
    ck_assert_str_eq((const char *) xlist->root->data, "item1");
    ck_assert_str_eq((const char *) xlist->end->data, "item1");

    rc = ssh_list_append(xlist, "item2");
    ck_assert(rc == 0);
    ck_assert_str_eq((const char *) xlist->root->data, "item1");
    ck_assert_str_eq((const char *) xlist->end->data, "item2");

    rc = ssh_list_append(xlist, "item3");
    ck_assert(rc == 0);
    ck_assert_str_eq((const char *) xlist->root->data, "item1");
    ck_assert_str_eq((const char *) xlist->root->next->data, "item2");
    ck_assert_str_eq((const char *) xlist->root->next->next->data, "item3");
    ck_assert_str_eq((const char *) xlist->end->data, "item3");

    ssh_list_free(xlist);
}
END_TEST

START_TEST(torture_ssh_list_prepend)
{
    struct ssh_list *xlist;
    int rc;

    xlist = ssh_list_new();
    ck_assert(xlist != NULL);

    rc = ssh_list_prepend(xlist, "item1");
    ck_assert(rc == 0);
    ck_assert_str_eq((const char *) xlist->root->data, "item1");
    ck_assert_str_eq((const char *) xlist->end->data, "item1");

    rc = ssh_list_append(xlist, "item2");
    ck_assert(rc == 0);
    ck_assert_str_eq((const char *) xlist->root->data, "item1");
    ck_assert_str_eq((const char *) xlist->end->data, "item2");

    rc = ssh_list_prepend(xlist, "item3");
    ck_assert(rc == 0);
    ck_assert_str_eq((const char *) xlist->root->data, "item3");
    ck_assert_str_eq((const char *) xlist->root->next->data, "item1");
    ck_assert_str_eq((const char *) xlist->root->next->next->data, "item2");
    ck_assert_str_eq((const char *) xlist->end->data, "item2");

    ssh_list_free(xlist);
}
END_TEST

static Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_list");

  torture_create_case(s, "torture_ssh_list_new", torture_ssh_list_new);
  torture_create_case(s, "torture_ssh_list_append", torture_ssh_list_append);
  torture_create_case(s, "torture_ssh_list_prepend", torture_ssh_list_prepend);

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

