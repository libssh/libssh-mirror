#include <sys/types.h>
#include <pwd.h>

#define LIBSSH_STATIC
#include <libssh/priv.h>

#include "torture.h"
#include "misc.c"
#define DIR "/usr/local/bin/truc/much/.."

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

START_TEST (torture_basename)
{
    char *path;
    path=ssh_basename(DIR "/test");
    ck_assert(path != NULL);
    ck_assert_str_eq(path, "test");
    SAFE_FREE(path);
    path=ssh_basename(DIR "/test/");
    ck_assert(path != NULL);
    ck_assert_str_eq(path, "test");
    SAFE_FREE(path);
}
END_TEST

START_TEST (torture_dirname)
{
    char *path;
    path=ssh_dirname(DIR "/test");
    ck_assert(path != NULL);
    ck_assert_str_eq(path, DIR );
    SAFE_FREE(path);
    path=ssh_dirname(DIR "/test/");
    ck_assert(path != NULL);
    ck_assert_str_eq(path, DIR);
    SAFE_FREE(path);
}
END_TEST

START_TEST (torture_ntohll)
{
    u_int32_t sample = 1;
    unsigned char *ptr=(unsigned char *) &sample;
    u_int64_t value = 0x0123456789abcdef;
    u_int64_t check;
    if(ptr[0]==1){
      /* we're in little endian */
      check = 0xefcdab8967452301;
    } else {
      /* big endian */
      check = value;
    }
    value=ntohll(value);
    ck_assert(value == check);
}
END_TEST

static Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_misc");

  torture_create_case(s, "torture_get_user_home_dir", torture_get_user_home_dir);
  torture_create_case(s, "torture_basename", torture_basename);
  torture_create_case(s, "torture_dirname", torture_dirname);
  torture_create_case(s, "torture_ntohll", torture_ntohll);

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

