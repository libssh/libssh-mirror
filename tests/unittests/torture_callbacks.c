#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/priv.h>
#include <libssh/callbacks.h>

static int myauthcallback (const char *prompt, char *buf, size_t len,
    int echo, int verify, void *userdata){
	(void) prompt;
	(void) buf;
	(void) len;
	(void) echo;
	(void) verify;
	(void) userdata;
	return 0;
}

struct ssh_callbacks_struct callbacks =
{
		.userdata=(void *)0x0badc0de,
		.auth_function=myauthcallback
};

static void setup(void) {
	ssh_callbacks_init(&callbacks);
}

static void teardown(void) {

}

START_TEST (torture_callbacks_size)
{
	ck_assert_int_ne(callbacks.size,0);
}
END_TEST

START_TEST (torture_callbacks_exists)
{
	ck_assert_int_ne(ssh_callbacks_exists(&callbacks,auth_function),0);
	ck_assert_int_eq(ssh_callbacks_exists(&callbacks,log_function),0);
	/* we redefine size so auth_function is outside the range of callbacks->size */
  callbacks.size=(unsigned char *)&(callbacks.auth_function) - (unsigned char *)&callbacks;
  ck_assert_int_eq(ssh_callbacks_exists(&callbacks,auth_function),0);
  /* now make it one pointer bigger so we spill over the auth_function slot */
  callbacks.size += sizeof(void *);
  ck_assert_int_ne(ssh_callbacks_exists(&callbacks,auth_function),0);
}
END_TEST

Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_options");

  torture_create_case_fixture(s, "torture_callbacks_size",
          torture_callbacks_size, setup, teardown);
  torture_create_case_fixture(s, "torture_callbacks_exists",
          torture_callbacks_exists, setup, teardown);

  return s;
}

