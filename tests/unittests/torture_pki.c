#define LIBSSH_STATIC

#include "torture.h"
#include "pki.c"
#include <sys/stat.h>
#include <fcntl.h>

#define LIBSSH_RSA_TESTKEY "libssh_testkey.id_rsa"
#define LIBSSH_DSA_TESTKEY "libssh_testkey.id_dsa"
#define LIBSSH_ECDSA_TESTKEY "libssh_testkey.id_ecdsa"
#define LIBSSH_ED25519_TESTKEY "libssh_testkey.id_ed25519"

const unsigned char HASH[] = "12345678901234567890";

static int setup_rsa_key(void **state)
{
    (void) state; /* unused */

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");
    unlink(LIBSSH_RSA_TESTKEY "-cert.pub");

    torture_write_file(LIBSSH_RSA_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_RSA, 0, 0));
    torture_write_file(LIBSSH_RSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_RSA, 0));
    torture_write_file(LIBSSH_RSA_TESTKEY "-cert.pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_RSA_CERT01, 0));

    return 0;
}

static int setup_dsa_key(void **state) {
    (void) state; /* unused */

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");
    unlink(LIBSSH_DSA_TESTKEY "-cert.pub");

    torture_write_file(LIBSSH_DSA_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_DSS, 0, 0));
    torture_write_file(LIBSSH_DSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS, 0));
    torture_write_file(LIBSSH_DSA_TESTKEY "-cert.pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS_CERT01, 0));

    return 0;
}

#ifdef HAVE_ECC
static int setup_ecdsa_key(void **state, int ecdsa_bits) {

    (void) state; /* unused */

    unlink(LIBSSH_ECDSA_TESTKEY);
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");

    torture_write_file(LIBSSH_ECDSA_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_ECDSA, ecdsa_bits, 0));
    torture_write_file(LIBSSH_ECDSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_ECDSA, ecdsa_bits));

    return 0;
}

static int setup_ecdsa_key_521(void **state) {
    setup_ecdsa_key(state, 521);

    return 0;
}

static int setup_ecdsa_key_384(void **state) {
    setup_ecdsa_key(state, 384);

    return 0;
}

static int setup_ecdsa_key_256(void **state) {
    setup_ecdsa_key(state, 256);

    return 0;
}
#endif

static int setup_ed25519_key(void **state) {
    (void) state; /* unused */

    unlink(LIBSSH_ED25519_TESTKEY);
    unlink(LIBSSH_ED25519_TESTKEY ".pub");

    torture_write_file(LIBSSH_ED25519_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_ED25519, 0,0));

    torture_write_file(LIBSSH_ED25519_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_ED25519,0));

    return 0;
}

static int setup_both_keys(void **state) {
    (void) state; /* unused */

    setup_rsa_key(state);
    setup_dsa_key(state);

    return 0;
}

static int teardown(void **state) {
    (void) state; /* unused */

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");
    unlink(LIBSSH_DSA_TESTKEY "-cert.pub");

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");
    unlink(LIBSSH_RSA_TESTKEY "-cert.pub");

    unlink(LIBSSH_ECDSA_TESTKEY);
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");

    return 0;
}

static char *read_file(const char *filename) {
    char *key;
    int fd;
    int size;
    int rc;
    struct stat sb;

    assert_true(filename != NULL);
    assert_true(*filename != '\0');

    fd = open(filename, O_RDONLY);
    assert_true(fd >= 0);

    rc = fstat(fd, &sb);
    assert_int_equal(rc, 0);

    key = malloc(sb.st_size + 1);
    assert_true(key != NULL);

    size = read(fd, key, sb.st_size);
    assert_true(size == sb.st_size);

    close(fd);

    key[size] = '\0';
    return key;
}

static int torture_read_one_line(const char *filename, char *buffer, size_t len) {
  FILE *fp;
  size_t nmemb;

  fp = fopen(filename, "r");
  if (fp == NULL) {
    return -1;
  }

  nmemb = fread(buffer, len - 2, 1, fp);
  if (nmemb != 0 || ferror(fp)) {
    fclose(fp);
    return -1;
  }
  buffer[len - 1] = '\0';

  fclose(fp);

  return 0;
}

/** @internal
 * returns the character len of a public key string, omitting the comment part
 */
static int torture_pubkey_len(const char *pubkey){
    const char *ptr;
    ptr=strchr(pubkey, ' ');
    if (ptr != NULL){
        ptr = strchr(ptr + 1, ' ');
        if (ptr != NULL){
            return ptr - pubkey;
        }
    }
    return 0;
}

static void torture_pki_keytype(void **state) {
    enum ssh_keytypes_e type;
    const char *type_c;

    (void) state; /* unused */

    type = ssh_key_type(NULL);
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type = ssh_key_type_from_name(NULL);
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type = ssh_key_type_from_name("42");
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type_c = ssh_key_type_to_char(SSH_KEYTYPE_UNKNOWN);
    assert_true(type_c == NULL);

    type_c = ssh_key_type_to_char(42);
    assert_true(type_c == NULL);
}

static void torture_pki_signature(void **state)
{
    ssh_signature sig;

    (void) state; /* unused */

    sig = ssh_signature_new();
    assert_true(sig != NULL);

    ssh_signature_free(sig);
}

static void torture_pki_import_privkey_base64_RSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = torture_get_testkey_passphrase();
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_RSA);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_key_is_public(key);
    assert_true(rc == 1);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_NULL_key(void **state) {
    int rc;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    /* test if it returns -1 if key is NULL */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 0, 0),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       NULL);
    assert_true(rc == -1);

}

static void torture_pki_import_privkey_base64_NULL_str(void **state) {
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    /* test if it returns -1 if key_str is NULL */
    rc = ssh_pki_import_privkey_base64(NULL, passphrase, NULL, NULL, &key);
    assert_true(rc == -1);

    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_DSA(void **state) {
    int rc;
    ssh_key key;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 0),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    ssh_key_free(key);
}

#ifdef HAVE_ECC
static void torture_pki_import_privkey_base64_ECDSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    key_str = read_file(LIBSSH_ECDSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    free(key_str);
    ssh_key_free(key);
}
#endif

static void torture_pki_import_privkey_base64_passphrase(void **state) {
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */


    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 0, 1),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_return_code(rc, errno);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    ssh_key_free(key);
    key = NULL;

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 0, 1),
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 0, 1),
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
#endif

    /* same for DSA */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 1),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_return_code(rc, errno);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    ssh_key_free(key);
    key = NULL;

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 1),
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 1),
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
#endif

    /* same for ED25519 */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_ED25519, 0, 1),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    ssh_key_free(key);
    key = NULL;

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_ED25519, 0, 1),
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);

}

static void torture_pki_import_privkey_base64_ed25519(void **state){
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = torture_get_testkey_passphrase();
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_ED25519_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ED25519);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_key_is_public(key);
    assert_true(rc == 1);

    free(key_str);
    ssh_key_free(key);

}

static void torture_pki_pki_publickey_from_privatekey_RSA(void **state) {
    int rc;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 0, 0),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    ssh_key_free(key);
    ssh_key_free(pubkey);
}

static void torture_pki_pki_publickey_from_privatekey_DSA(void **state) {
    int rc;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0, 0),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    ssh_key_free(key);
    ssh_key_free(pubkey);
}

static void torture_pki_pki_publickey_from_privatekey_ed25519(void **state){
    int rc;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_ED25519, 0, 0),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    ssh_key_free(key);
    ssh_key_free(pubkey);
}

#ifdef HAVE_ECC
static void torture_pki_publickey_from_privatekey_ECDSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_ECDSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    free(key_str);
    ssh_key_free(key);
    ssh_key_free(pubkey);
}
#endif

static void torture_pki_copy_cert_to_privkey(void **state) {
    /* Tests copying a cert loaded into a public key to a private key.
       The function is encryption type agnostic, no need to run this
       against all supported key types.
     */
    int rc;
    const char *passphrase = torture_get_testkey_passphrase();
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key cert;

    (void) state; /* unused */

    rc = ssh_pki_import_cert_file(LIBSSH_RSA_TESTKEY "-cert.pub", &cert);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_import_pubkey_file(LIBSSH_RSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 0, 0),
				       passphrase,
				       NULL,
				       NULL,
				       &privkey);
    assert_true(rc == SSH_OK);

    /* Basic sanity. */
    rc = ssh_pki_copy_cert_to_privkey(NULL, privkey);
    assert_true(rc == SSH_ERROR);

    rc = ssh_pki_copy_cert_to_privkey(pubkey, NULL);
    assert_true(rc == SSH_ERROR);

    /* A public key doesn't have a cert, copy should fail. */
    assert_true(pubkey->cert == NULL);
    rc = ssh_pki_copy_cert_to_privkey(pubkey, privkey);
    assert_true(rc == SSH_ERROR);

    /* Copying the cert to non-cert keys should work fine. */
    rc = ssh_pki_copy_cert_to_privkey(cert, pubkey);
    assert_true(rc == SSH_OK);
    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_true(rc == SSH_OK);

    /* The private key's cert is already set, another copy should fail. */
    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_true(rc == SSH_ERROR);

    ssh_key_free(cert);
    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}

static void torture_pki_import_cert_file_rsa(void **state) {
    int rc;
    ssh_key cert;
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    rc = ssh_pki_import_cert_file(LIBSSH_RSA_TESTKEY "-cert.pub", &cert);
    assert_true(rc == 0);

    type = ssh_key_type(cert);
    assert_true(type == SSH_KEYTYPE_RSA_CERT01);

    rc = ssh_key_is_public(cert);
    assert_true(rc == 1);

    ssh_key_free(cert);
}

static void torture_pki_import_cert_file_dsa(void **state) {
    int rc;
    ssh_key cert;
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    rc = ssh_pki_import_cert_file(LIBSSH_DSA_TESTKEY "-cert.pub", &cert);
    assert_true(rc == 0);

    type = ssh_key_type(cert);
    assert_true(type == SSH_KEYTYPE_DSS_CERT01);

    rc = ssh_key_is_public(cert);
    assert_true(rc == 1);

    ssh_key_free(cert);
}

static void torture_pki_publickey_dsa_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = strdup(torture_get_testkey_pub(SSH_KEYTYPE_DSS, 0));
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_DSS);

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}

#ifdef HAVE_ECC
static void torture_pki_publickey_ecdsa_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = read_file(LIBSSH_ECDSA_TESTKEY ".pub");
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_ECDSA);

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}
#endif

static void torture_pki_publickey_rsa_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = strdup(torture_get_testkey_pub(SSH_KEYTYPE_RSA, 0));
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(((type == SSH_KEYTYPE_RSA) ||
                 (type == SSH_KEYTYPE_RSA1)));

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}

static void torture_pki_publickey_ed25519_base64(void **state){
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = strdup(torture_get_testkey_pub(SSH_KEYTYPE_ED25519, 0));
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_ED25519);

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}

static void torture_generate_pubkey_from_privkey_rsa(void **state) {
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int rc;
    int len;

    (void) state; /* unused */

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_RSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    len = torture_pubkey_len(torture_get_testkey_pub(SSH_KEYTYPE_RSA, 0));
    assert_memory_equal(torture_get_testkey_pub(SSH_KEYTYPE_RSA, 0),
                        pubkey_generated,
                        len);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}

static void torture_generate_pubkey_from_privkey_dsa(void **state) {
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int len;
    int rc;

    (void) state; /* unused */

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_DSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_DSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    len = torture_pubkey_len(torture_get_testkey_pub(SSH_KEYTYPE_DSS, 0));
    assert_memory_equal(torture_get_testkey_pub(SSH_KEYTYPE_DSS, 0),
                        pubkey_generated,
                        len);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}

static void torture_generate_pubkey_from_privkey_ed25519(void **state){
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int rc;
    int len;

    (void) state; /* unused */

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_ED25519_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_ED25519_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_ED25519_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    len = torture_pubkey_len(torture_get_testkey_pub(SSH_KEYTYPE_ED25519, 0));
    assert_memory_equal(torture_get_testkey_pub(SSH_KEYTYPE_ED25519, 0),
                        pubkey_generated,
                        len);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}

#ifdef HAVE_ECC
static void torture_generate_pubkey_from_privkey_ecdsa(void **state) {
    char pubkey_original[4096] = {0};
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int rc;
    int len;

    (void) state; /* unused */

    rc = torture_read_one_line(LIBSSH_ECDSA_TESTKEY ".pub",
                               pubkey_original,
                               sizeof(pubkey_original));
    assert_true(rc == 0);

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_ECDSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_ECDSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);
    len = torture_pubkey_len(pubkey_original);
    assert_int_equal(strncmp(pubkey_original, pubkey_generated, len), 0);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}
#endif

static void torture_pki_duplicate_key_rsa(void **state)
{
    int rc;
    char *b64_key;
    char *b64_key_gen;
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_RSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    ssh_key_free(pubkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
    ssh_string_free_char(b64_key);
    ssh_string_free_char(b64_key_gen);
}

static void torture_pki_duplicate_key_dsa(void **state)
{
    int rc;
    char *b64_key;
    char *b64_key_gen;
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_DSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    ssh_key_free(pubkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
    ssh_string_free_char(b64_key);
    ssh_string_free_char(b64_key_gen);
}

#ifdef HAVE_ECC
static void torture_pki_duplicate_key_ecdsa(void **state)
{
    int rc;
    char *b64_key;
    char *b64_key_gen;
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_ECDSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    ssh_key_free(pubkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
    ssh_string_free_char(b64_key);
    ssh_string_free_char(b64_key_gen);
}

/* Test case for bug #147: Private ECDSA key duplication did not carry
 * over parts of the key that then caused subsequent key demotion to
 * fail.
 */
static void torture_pki_ecdsa_duplicate_then_demote(void **state)
{
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;
    int rc;

    (void) state;

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);
    assert_int_equal(privkey->ecdsa_nid, privkey_dup->ecdsa_nid);

    rc = ssh_pki_export_privkey_to_pubkey(privkey_dup, &pubkey);
    assert_true(rc == 0);
    assert_int_equal(pubkey->ecdsa_nid, privkey->ecdsa_nid);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
}
#endif

static void torture_pki_generate_key_rsa(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 1024, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 4096, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

static void torture_pki_generate_key_rsa1(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA1, 1024, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA1, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA1, 4096, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

static void torture_pki_generate_key_dsa(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 1024, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 3072, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

#ifdef HAVE_ECC
static void torture_pki_generate_key_ecdsa(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    enum ssh_keytypes_e type = SSH_KEYTYPE_UNKNOWN;
    const char *type_char = NULL;
    const char *etype_char = NULL;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 256, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ECDSA);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ecdsa") == 0);
    etype_char = ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, "ecdsa-sha2-nistp256") == 0);

    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 384, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ECDSA);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ecdsa") == 0);
    etype_char =ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, "ecdsa-sha2-nistp384") == 0);

    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 512, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ECDSA);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ecdsa") == 0);
    etype_char =ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, "ecdsa-sha2-nistp521") == 0);

    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}
#endif

static void torture_pki_generate_key_ed25519(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    enum ssh_keytypes_e type = SSH_KEYTYPE_UNKNOWN;
    const char *type_char = NULL;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_ED25519, 256, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ED25519);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ed25519") == 0);

    /* try an invalid signature */
    (*sign->ed25519_sig)[3]^= 0xff;
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_ERROR);

    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

#ifdef HAVE_LIBCRYPTO
static void torture_pki_write_privkey_rsa(void **state)
{
    ssh_key origkey;
    ssh_key privkey;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_RSA_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
                                     "",
                                     NULL,
                                     NULL,
                                     LIBSSH_RSA_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(origkey);
    ssh_key_free(privkey);
}

static void torture_pki_write_privkey_dsa(void **state)
{
    ssh_key origkey;
    ssh_key privkey;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_DSA_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
                                     "",
                                     NULL,
                                     NULL,
                                     LIBSSH_DSA_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(origkey);
    ssh_key_free(privkey);
}

#ifdef HAVE_ECC
static void torture_pki_write_privkey_ecdsa(void **state)
{
    ssh_key origkey;
    ssh_key privkey;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_ECDSA_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
                                     "",
                                     NULL,
                                     NULL,
                                     LIBSSH_ECDSA_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(origkey);
    ssh_key_free(privkey);
}
#endif
#endif /* HAVE_LIBCRYPTO */

static void torture_pki_write_privkey_ed25519(void **state){
    ssh_key origkey;
    ssh_key privkey;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            NULL,
            NULL,
            NULL,
            &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_ED25519_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
            NULL,
            NULL,
            NULL,
            LIBSSH_ED25519_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            NULL,
            NULL,
            NULL,
            &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    unlink(LIBSSH_ED25519_TESTKEY);
    ssh_key_free(privkey);
    /* do the same with passphrase */
    rc = ssh_pki_export_privkey_file(origkey,
            torture_get_testkey_passphrase(),
            NULL,
            NULL,
            LIBSSH_ED25519_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            NULL,
            NULL,
            NULL,
            &privkey);
    /* opening without passphrase should fail */
    assert_true(rc == SSH_ERROR);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            torture_get_testkey_passphrase(),
            NULL,
            NULL,
            &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);
    unlink(LIBSSH_ED25519_TESTKEY);

    ssh_key_free(origkey);
    ssh_key_free(privkey);
}

#ifdef HAVE_ECC
static void torture_pki_ecdsa_name(void **state, const char *expected_name)
{
    int rc;
    ssh_key key;
    const char *etype_char = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY, NULL, NULL, NULL, &key);
    assert_true(rc == 0);

    etype_char =ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, expected_name) == 0);

    ssh_key_free(key);
}

static void torture_pki_ecdsa_name256(void **state)
{
    torture_pki_ecdsa_name(state, "ecdsa-sha2-nistp256");
}

static void torture_pki_ecdsa_name384(void **state)
{
    torture_pki_ecdsa_name(state, "ecdsa-sha2-nistp384");
}

static void torture_pki_ecdsa_name521(void **state)
{
    torture_pki_ecdsa_name(state, "ecdsa-sha2-nistp521");
}
#endif

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_pki_keytype),

        cmocka_unit_test(torture_pki_signature),

        /* ssh_pki_import_privkey_base64 */
        cmocka_unit_test_setup_teardown(torture_pki_import_privkey_base64_NULL_key,
                                 setup_rsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_import_privkey_base64_NULL_str,
                                 setup_rsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_import_privkey_base64_RSA,
                                 setup_rsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_import_privkey_base64_DSA,
                                 setup_dsa_key,
                                 teardown),
#ifdef HAVE_ECC
        cmocka_unit_test_setup_teardown(torture_pki_import_privkey_base64_ECDSA,
                                 setup_ecdsa_key_256,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_import_privkey_base64_ECDSA,
                                 setup_ecdsa_key_384,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_import_privkey_base64_ECDSA,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
        cmocka_unit_test_setup_teardown(torture_pki_import_privkey_base64_ed25519,
                                setup_ed25519_key,
                                teardown),
        cmocka_unit_test(torture_pki_import_privkey_base64_passphrase),
        /* ssh_pki_export_privkey_to_pubkey */
        cmocka_unit_test_setup_teardown(torture_pki_pki_publickey_from_privatekey_RSA,
                                 setup_rsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_pki_publickey_from_privatekey_DSA,
                                 setup_dsa_key,
                                 teardown),
#ifdef HAVE_ECC
        cmocka_unit_test_setup_teardown(torture_pki_publickey_from_privatekey_ECDSA,
                                 setup_ecdsa_key_256,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_publickey_from_privatekey_ECDSA,
                                 setup_ecdsa_key_384,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_publickey_from_privatekey_ECDSA,
                                 setup_ecdsa_key_521,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_duplicate_then_demote,
                                 setup_ecdsa_key_256,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_duplicate_then_demote,
                                 setup_ecdsa_key_384,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_duplicate_then_demote,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
        cmocka_unit_test_setup_teardown(torture_pki_pki_publickey_from_privatekey_ed25519,
                                 setup_ed25519_key,
                                 teardown),
        /* cert */
        cmocka_unit_test_setup_teardown(torture_pki_copy_cert_to_privkey,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_import_cert_file_rsa,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_import_cert_file_dsa,
                                        setup_dsa_key,
                                        teardown),

        /* public key */
        cmocka_unit_test_setup_teardown(torture_pki_publickey_dsa_base64,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_publickey_rsa_base64,
                                 setup_rsa_key,
                                 teardown),
#ifdef HAVE_ECC
        cmocka_unit_test_setup_teardown(torture_pki_publickey_ecdsa_base64,
                                 setup_ecdsa_key_256,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_publickey_ecdsa_base64,
                                 setup_ecdsa_key_384,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_publickey_ecdsa_base64,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
        cmocka_unit_test_setup_teardown(torture_pki_publickey_ed25519_base64,
                                 setup_ed25519_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_generate_pubkey_from_privkey_dsa,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_generate_pubkey_from_privkey_rsa,
                                 setup_rsa_key,
                                 teardown),
#ifdef HAVE_ECC
        cmocka_unit_test_setup_teardown(torture_generate_pubkey_from_privkey_ecdsa,
                                 setup_ecdsa_key_256,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_generate_pubkey_from_privkey_ecdsa,
                                 setup_ecdsa_key_384,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_generate_pubkey_from_privkey_ecdsa,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
        cmocka_unit_test_setup_teardown(torture_generate_pubkey_from_privkey_ed25519,
                                 setup_rsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_duplicate_key_rsa,
                                 setup_rsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_duplicate_key_dsa,
                                 setup_dsa_key,
                                 teardown),
#ifdef HAVE_ECC
        cmocka_unit_test_setup_teardown(torture_pki_duplicate_key_ecdsa,
                                 setup_ecdsa_key_256,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_duplicate_key_ecdsa,
                                 setup_ecdsa_key_384,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_duplicate_key_ecdsa,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
        cmocka_unit_test_setup_teardown(torture_pki_duplicate_key_dsa,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test(torture_pki_generate_key_rsa),
        cmocka_unit_test(torture_pki_generate_key_rsa1),
        cmocka_unit_test(torture_pki_generate_key_dsa),
#ifdef HAVE_ECC
        cmocka_unit_test(torture_pki_generate_key_ecdsa),
#endif
        cmocka_unit_test(torture_pki_generate_key_ed25519),
#ifdef HAVE_LIBCRYPTO
        cmocka_unit_test_setup_teardown(torture_pki_write_privkey_rsa,
                                 setup_rsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_write_privkey_dsa,
                                 setup_dsa_key,
                                 teardown),
#ifdef HAVE_ECC
        cmocka_unit_test_setup_teardown(torture_pki_write_privkey_ecdsa,
                                 setup_ecdsa_key_256,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_write_privkey_ecdsa,
                                 setup_ecdsa_key_384,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_write_privkey_ecdsa,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
#endif /* HAVE_LIBCRYPTO */
        cmocka_unit_test_setup_teardown(torture_pki_write_privkey_ed25519,
                                 setup_dsa_key,
                                 teardown),

#ifdef HAVE_ECC
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_name256,
                                 setup_ecdsa_key_256,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_name384,
                                 setup_ecdsa_key_384,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ecdsa_name521,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
    };

    (void)setup_both_keys;

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
