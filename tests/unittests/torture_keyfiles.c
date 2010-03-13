#define LIBSSH_STATIC

#include "torture.h"
#include "keyfiles.c"

#define LIBSSH_RSA_TESTKEY "libssh_testkey.id_rsa"
#define LIBSSH_DSA_TESTKEY "libssh_testkey.id_dsa"

ssh_session session;

static void setup(void) {
    session = ssh_new();
}

static void setup_rsa_key(void) {
    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    system("ssh-keygen -t rsa -N \"\" -f " LIBSSH_RSA_TESTKEY);

    session = ssh_new();
}

static void setup_dsa_key(void) {
    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    system("ssh-keygen -t dsa -N \"\" -f " LIBSSH_RSA_TESTKEY);

    session = ssh_new();
}

static void teardown(void) {
    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    ssh_free(session);
}

START_TEST (torture_pubkey_from_file)
{
    ssh_string pubkey;
    int type, rc;

    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey, &type);

    ck_assert(rc == 0);

    string_free(pubkey);

    /* test if it returns 1 if pubkey doesn't exist */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey, &type);
    ck_assert(rc == 1);

    /* test if it returns -1 if privkey doesn't exist */
    unlink(LIBSSH_RSA_TESTKEY);

    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey, &type);
    ck_assert(rc == -1);
}
END_TEST

static int torture_read_one_line(const char *filename, char *buffer, size_t len) {
  FILE *fp;
  size_t rc;

  fp = fopen(filename, "r");
  if (fp == NULL) {
    return -1;
  }

  rc = fread(buffer, len, 1, fp);
  if (rc != 0 || ferror(fp)) {
    fclose(fp);
    return -1;
  }

  fclose(fp);

  return 0;
}

START_TEST (torture_pubkey_generate_from_privkey)
{
    ssh_private_key privkey = NULL;
    ssh_public_key pubkey = NULL;
    ssh_string pubkey_orig = NULL;
    ssh_string pubkey_new = NULL;
    char pubkey_line_orig[512] = {0};
    char pubkey_line_new[512] = {0};
    int type_orig = 0;
    int type_new = 0;
    int rc;

    /* read the publickey */
    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey_orig,
        &type_orig);
    ck_assert(rc == 0);
    ck_assert(pubkey_orig != NULL);

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub", pubkey_line_orig,
        sizeof(pubkey_line_orig));
    ck_assert(rc == 0);

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    privkey = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, 0, NULL);
    ck_assert(privkey != NULL);

    pubkey = publickey_from_privatekey(privkey);
    type_new = privkey->type;
    privatekey_free(privkey);
    ck_assert(pubkey != NULL);

    pubkey_new = publickey_to_string(pubkey);
    publickey_free(pubkey);

    ck_assert(pubkey_new != NULL);
    ck_assert(memcmp(pubkey_orig->string, pubkey_new->string, pubkey_orig->size));

    rc = ssh_publickey_to_file(session, LIBSSH_RSA_TESTKEY ".pub", pubkey_new, type_new);
    ck_assert(rc == 0);

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub", pubkey_line_new,
        sizeof(pubkey_line_new));

    ck_assert_str_eq(pubkey_line_orig, pubkey_line_new);

    string_free(pubkey_orig);
    string_free(pubkey_new);
}
END_TEST

static Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_keyfiles");

  torture_create_case_fixture(s, "torture_pubkey_from_file",
          torture_pubkey_from_file, setup_rsa_key, teardown);
  torture_create_case_fixture(s, "torture_pubkey_generate_from_privkey",
          torture_pubkey_generate_from_privkey, setup_rsa_key, teardown);

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

