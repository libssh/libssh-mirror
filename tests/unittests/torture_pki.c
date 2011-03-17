#define LIBSSH_STATIC

#include "torture.h"
#include "pki.c"
#include <sys/stat.h>
#include <fcntl.h>

#define LIBSSH_RSA_TESTKEY "libssh_testkey.id_rsa"
#define LIBSSH_DSA_TESTKEY "libssh_testkey.id_dsa"
#define LIBSSH_PASSPHRASE "libssh-rocks"

static void setup_rsa_key(void **state) {
    ssh_session session;
    int rc;

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = system("ssh-keygen -t rsa -q -N \"\" -f " LIBSSH_RSA_TESTKEY);
    assert_true(rc == 0);

    session = ssh_new();
    *state = session;
}

static void setup_dsa_key(void **state) {
    ssh_session session;
    int rc;

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    rc = system("ssh-keygen -t dsa -q -N \"\" -f " LIBSSH_DSA_TESTKEY);
    assert_true(rc == 0);

    session = ssh_new();
    *state = session;
}

static void setup_both_keys(void **state) {
    setup_rsa_key(state);
    ssh_free(*state);
    setup_dsa_key(state);
}

static void setup_both_keys_passphrase(void **state) {
    ssh_session session;
    int rc;

    rc = system("ssh-keygen -t rsa -q -N " LIBSSH_PASSPHRASE " -f " LIBSSH_RSA_TESTKEY);
    assert_true(rc == 0);

    rc = system("ssh-keygen -t dsa -q -N " LIBSSH_PASSPHRASE " -f " LIBSSH_DSA_TESTKEY);
    assert_true(rc == 0);

    session = ssh_new();
    *state = session;
}

static void teardown(void **state) {
    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    ssh_free(*state);
}

static char *read_file(const char *filename) {
    char *key;
    int fd;
    int size;
    struct stat buf;

    assert_true(filename != NULL);
    assert_true(*filename != '\0');

    stat(filename, &buf);

    key = malloc(buf.st_size + 1);
    assert_true(key != NULL);

    fd = open(filename, O_RDONLY);
    assert_true(fd >= 0);

    size = read(fd, key, buf.st_size);
    assert_true(size == buf.st_size);

    close(fd);

    key[size] = '\0';
    return key;
}

static void torture_pki_import_privkey_base64_RSA(void **state) {
    ssh_session session = *state;
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    key = ssh_key_new();
    assert_true(key != NULL);
    /* 
    int ssh_pki_import_privkey_base64(ssh_key key, ssh_session session,
                    const char *b64_key, const char *passphrase)
    */
    rc = ssh_pki_import_privkey_base64(key, session, key_str, passphrase);
    assert_true(rc == 0);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_NULL_key(void **state) {
    ssh_session session = *state;
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    key = ssh_key_new();
    assert_true(key != NULL);

    /* test if it returns -1 if key is NULL */
    rc = ssh_pki_import_privkey_base64(NULL, session, key_str, passphrase);
    assert_true(rc == -1);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_NULL_session(void **state) {
    ssh_session session = *state;
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    key = ssh_key_new();
    assert_true(key != NULL);

    /* test if it returns -1 if session is NULL */
    (void)session;
    rc = ssh_pki_import_privkey_base64(key, NULL, key_str, passphrase);
    assert_true(rc == -1);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_NULL_str(void **state) {
    ssh_session session = *state;
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    key = ssh_key_new();
    assert_true(key != NULL);

    /* test if it returns -1 if key_str is NULL */
    rc = ssh_pki_import_privkey_base64(key, session, NULL, passphrase);
    assert_true(rc == -1);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_DSA(void **state) {
    ssh_session session = *state;
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;

    key_str = read_file(LIBSSH_DSA_TESTKEY);
    assert_true(key_str != NULL);

    key = ssh_key_new();
    assert_true(key != NULL);
    /* 
    int ssh_pki_import_privkey_base64(ssh_key key, ssh_session session,
                    const char *b64_key, const char *passphrase)
    */
    rc = ssh_pki_import_privkey_base64(key, session, key_str, passphrase);
    assert_true(rc == 0);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_passphrase(void **state) {
    ssh_session session = *state;
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    key = ssh_key_new();
    assert_true(key != NULL);

    rc = ssh_pki_import_privkey_base64(key, session, key_str, passphrase);
    assert_true(rc == 0);

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(key, session, key_str, "wrong passphrase !!");
    assert_true(rc == -1);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(key, session, key_str, NULL);
    assert_true(rc == -1);
#endif

    free(key_str);

    /* same for DSA */
    key_str = read_file(LIBSSH_DSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key, session, key_str, passphrase);
    assert_true(rc == 0);

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(key, session, key_str, "wrong passphrase !!");
    assert_true(rc == -1);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(key, session, key_str, NULL);
    assert_true(rc == -1);
#endif

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_pki_publickey_from_privatekey_RSA(void **state) {
    ssh_session session = *state;
    int rc;
    char *key_str;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    key = ssh_key_new();
    assert_true(key != NULL);

    rc = ssh_pki_import_privkey_base64(key, session, key_str, passphrase);
    assert_true(rc == 0);

    pubkey = ssh_pki_publickey_from_privatekey(key);
    assert_true(pubkey != NULL);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_pki_publickey_from_privatekey_DSA(void **state) {
    ssh_session session = *state;
    int rc;
    char *key_str;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    key_str = read_file(LIBSSH_DSA_TESTKEY);
    assert_true(key_str != NULL);

    key = ssh_key_new();
    assert_true(key != NULL);

    rc = ssh_pki_import_privkey_base64(key, session, key_str, passphrase);
    assert_true(rc == 0);

    pubkey = ssh_pki_publickey_from_privatekey(key);
    assert_true(pubkey != NULL);

    free(key_str);
    ssh_key_free(key);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        /* ssh_pki_import_privkey_base64 */
        unit_test_setup_teardown(torture_pki_import_privkey_base64_NULL_key,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_NULL_session,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_NULL_str,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_RSA,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_DSA,
                                 setup_dsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_passphrase,
                                 setup_both_keys_passphrase,
                                 teardown),
        /* ssh_pki_publickey_from_privatekey */
        unit_test_setup_teardown(torture_pki_pki_publickey_from_privatekey_RSA,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_pki_publickey_from_privatekey_DSA,
                                 setup_dsa_key,
                                 teardown),



    };

    (void)setup_both_keys;

    ssh_init();
    rc=run_tests(tests);
    ssh_finalize();
    return rc;
}
