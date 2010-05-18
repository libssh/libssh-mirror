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

Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_init");

  torture_create_case(s, "torture_ssh_init", torture_ssh_init);

  return s;
}



