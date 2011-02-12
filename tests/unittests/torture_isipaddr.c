#define LIBSSH_STATIC

#include "torture.h"

#include "connect.c"

/*
 * Test the behavior of isipaddr()
 */
static void torture_isipaddr(void **state) {
  (void)state;
  assert_int_equal(isipaddr("127.0.0.1"),1);
  assert_int_equal(isipaddr("0.0.0.0"),1);
  assert_int_equal(isipaddr("1.1.1.1"),1);
  assert_int_equal(isipaddr("255.255.255.255"),1);
  assert_int_equal(isipaddr("128.128.128.128"),1);
  assert_int_equal(isipaddr("1.10.100.1"),1);
  assert_int_equal(isipaddr("0.1.10.100"),1);

  assert_int_equal(isipaddr("0.0.0.0.0"),0);
  assert_int_equal(isipaddr("0.0.0.0.a"),0);
  assert_int_equal(isipaddr("a.0.0.0"),0);
  assert_int_equal(isipaddr("0a.0.0.0.0"),0);
  assert_int_equal(isipaddr(""),0);
  assert_int_equal(isipaddr("0.0.0."),0);
  assert_int_equal(isipaddr("0.0.0"),0);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test(torture_isipaddr)
    };

    ssh_init();
    rc=run_tests(tests);
    ssh_finalize();
    return rc;
}
