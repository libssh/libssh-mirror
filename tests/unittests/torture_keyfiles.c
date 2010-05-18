#define LIBSSH_STATIC

#include "torture.h"
#include "keyfiles.c"

#define LIBSSH_RSA_TESTKEY "libssh_testkey.id_rsa"
#define LIBSSH_DSA_TESTKEY "libssh_testkey.id_dsa"
#define LIBSSH_PASSPHRASE "libssh-rocks"
ssh_session session;

#if 0
static void setup(void) {
    session = ssh_new();
}
#endif

static void setup_rsa_key(void) {
    int rc;

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = system("ssh-keygen -t rsa -q -N \"\" -f " LIBSSH_RSA_TESTKEY);

    session = ssh_new();
}

static void setup_dsa_key(void) {
    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    system("ssh-keygen -t dsa -q -N \"\" -f " LIBSSH_DSA_TESTKEY);

    session = ssh_new();
}

static void setup_both_keys(void) {
  setup_rsa_key();
  ssh_free(session);
  setup_dsa_key();
}

static void setup_both_keys_passphrase(void) {
  system("ssh-keygen -t rsa -N " LIBSSH_PASSPHRASE " -f " LIBSSH_RSA_TESTKEY);
  system("ssh-keygen -t dsa -N " LIBSSH_PASSPHRASE " -f " LIBSSH_DSA_TESTKEY);
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

    ck_assert_msg(rc == 0,ssh_get_error(session));

    ssh_string_free(pubkey);

    /* test if it returns 1 if pubkey doesn't exist */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey, &type);
    ck_assert_msg(rc == 1,ssh_get_error(session));

    /* test if it returns -1 if privkey doesn't exist */
    unlink(LIBSSH_RSA_TESTKEY);

    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey, &type);
    ck_assert_msg(rc == -1,ssh_get_error(session));
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
    ck_assert_msg(rc == 0,ssh_get_error(session));
    ck_assert(pubkey_orig != NULL);

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub", pubkey_line_orig,
        sizeof(pubkey_line_orig));
    ck_assert(rc == 0);

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    privkey = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, 0, NULL);
    ck_assert_msg(privkey != NULL,ssh_get_error(session));

    pubkey = publickey_from_privatekey(privkey);
    type_new = privkey->type;
    privatekey_free(privkey);
    ck_assert_msg(pubkey != NULL,ssh_get_error(session));

    pubkey_new = publickey_to_string(pubkey);
    publickey_free(pubkey);

    ck_assert_msg(pubkey_new != NULL,ssh_get_error(session));

    ck_assert(ssh_string_len(pubkey_orig) == ssh_string_len(pubkey_new));
    ck_assert(memcmp(ssh_string_data(pubkey_orig), ssh_string_data(pubkey_new),
                ssh_string_len(pubkey_orig)) == 0);

    rc = ssh_publickey_to_file(session, LIBSSH_RSA_TESTKEY ".pub", pubkey_new, type_new);
    ck_assert_msg(rc == 0,ssh_get_error(session));

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub", pubkey_line_new,
        sizeof(pubkey_line_new));

    ck_assert_str_eq(pubkey_line_orig, pubkey_line_new);

    ssh_string_free(pubkey_orig);
    ssh_string_free(pubkey_new);
}
END_TEST

/**
 * @brief tests the privatekey_from_file function without passphrase
 */
START_TEST(torture_privatekey_from_file){
  ssh_private_key key=NULL;
  key=privatekey_from_file(session, LIBSSH_RSA_TESTKEY, SSH_KEYTYPE_RSA, NULL);
  ck_assert_msg(key != NULL,ssh_get_error(session));
  if(key != NULL){
    privatekey_free(key);
    key=NULL;
  }
  key=privatekey_from_file(session, LIBSSH_DSA_TESTKEY, SSH_KEYTYPE_DSS, NULL);
  ck_assert_msg(key != NULL,ssh_get_error(session));
  if(key != NULL){
    privatekey_free(key);
    key=NULL;
  }
  /* test the automatic type discovery */
  key=privatekey_from_file(session, LIBSSH_RSA_TESTKEY, 0, NULL);
  ck_assert_msg(key != NULL,ssh_get_error(session));
  if(key != NULL){
    privatekey_free(key);
    key=NULL;
  }
  key=privatekey_from_file(session, LIBSSH_DSA_TESTKEY, 0, NULL);
  ck_assert_msg(key != NULL,ssh_get_error(session));
  if(key != NULL){
    privatekey_free(key);
    key=NULL;
  }

}
END_TEST

/**
 * @brief tests the privatekey_from_file function with passphrase
 */
START_TEST(torture_privatekey_from_file_passphrase){
  ssh_private_key key=NULL;
  key=privatekey_from_file(session, LIBSSH_RSA_TESTKEY, SSH_KEYTYPE_RSA, LIBSSH_PASSPHRASE);
  ck_assert_msg(key != NULL,ssh_get_error(session));
  if(key != NULL){
    privatekey_free(key);
    key=NULL;
  }
  key=privatekey_from_file(session, LIBSSH_DSA_TESTKEY, SSH_KEYTYPE_DSS, LIBSSH_PASSPHRASE);
  ck_assert_msg(key != NULL,ssh_get_error(session));
  if(key != NULL){
    privatekey_free(key);
    key=NULL;
  }
  /* test the automatic type discovery */
  key=privatekey_from_file(session, LIBSSH_RSA_TESTKEY, 0, LIBSSH_PASSPHRASE);
  ck_assert_msg(key != NULL,ssh_get_error(session));
  if(key != NULL){
    privatekey_free(key);
    key=NULL;
  }
  key=privatekey_from_file(session, LIBSSH_DSA_TESTKEY, 0, LIBSSH_PASSPHRASE);
  ck_assert_msg(key != NULL,ssh_get_error(session));
  if(key != NULL){
    privatekey_free(key);
    key=NULL;
  }

}
END_TEST

Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_keyfiles");

  torture_create_case_fixture(s, "torture_pubkey_from_file",
          torture_pubkey_from_file, setup_rsa_key, teardown);
  torture_create_case_fixture(s, "torture_pubkey_generate_from_privkey",
          torture_pubkey_generate_from_privkey, setup_rsa_key, teardown);
  torture_create_case_fixture(s, "torture_privkey_from_file",
          torture_privatekey_from_file, setup_both_keys, teardown);
  torture_create_case_fixture(s, "torture_privkey_from_file_passphrase",
            torture_privatekey_from_file_passphrase, setup_both_keys_passphrase, teardown);

  return s;
}

