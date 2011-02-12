#define LIBSSH_STATIC

#include "torture.h"

#include "misc.c"

/*
 * Test the behavior of ssh_is_ipaddr()
 */
static void torture_ssh_is_ipaddr(void **state) {
  (void)state;
  assert_int_equal(ssh_is_ipaddr("127.0.0.1"),1);
  assert_int_equal(ssh_is_ipaddr("0.0.0.0"),1);
  assert_int_equal(ssh_is_ipaddr("1.1.1.1"),1);
  assert_int_equal(ssh_is_ipaddr("255.255.255.255"),1);
  assert_int_equal(ssh_is_ipaddr("128.128.128.128"),1);
  assert_int_equal(ssh_is_ipaddr("1.10.100.1"),1);
  assert_int_equal(ssh_is_ipaddr("0.1.10.100"),1);

  assert_int_equal(ssh_is_ipaddr("0.0.0.0.0"),0);
  assert_int_equal(ssh_is_ipaddr("0.0.0.0.a"),0);
  assert_int_equal(ssh_is_ipaddr("a.0.0.0"),0);
  assert_int_equal(ssh_is_ipaddr("0a.0.0.0.0"),0);
  assert_int_equal(ssh_is_ipaddr(""),0);
  assert_int_equal(ssh_is_ipaddr("0.0.0."),0);
  assert_int_equal(ssh_is_ipaddr("0.0.0"),0);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test(torture_ssh_is_ipaddr)
    };

    ssh_init();
    rc=run_tests(tests);
    ssh_finalize();
    return rc;
}
