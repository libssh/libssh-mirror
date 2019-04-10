#include "config.h"

#define LIBSSH_STATIC

#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "torture_pki.h"
#include "torture_key.h"
#include "pki.c"

const unsigned char HASH[] = "1234567890123456789012345678901234567890"
                             "123456789012345678901234";

const char template[] = "temp_dir_XXXXXX";

struct pki_st {
    char *cwd;
    char *temp_dir;
};

static int setup_cert_dir(void **state)
{
    struct pki_st *test_state = NULL;
    char *cwd = NULL;
    char *tmp_dir = NULL;
    int rc = 0;

    test_state = (struct pki_st *)malloc(sizeof(struct pki_st));
    assert_non_null(test_state);

    cwd = torture_get_current_working_dir();
    assert_non_null(cwd);

    tmp_dir = torture_make_temp_dir(template);
    assert_non_null(tmp_dir);

    test_state->cwd = cwd;
    test_state->temp_dir = tmp_dir;

    *state = test_state;

    rc = torture_change_dir(tmp_dir);
    assert_int_equal(rc, 0);

    printf("Changed directory to: %s\n", tmp_dir);

    return 0;
}

static int teardown_cert_dir(void **state) {

    struct pki_st *test_state = NULL;
    int rc = 0;

    test_state = *((struct pki_st **)state);

    assert_non_null(test_state);
    assert_non_null(test_state->cwd);
    assert_non_null(test_state->temp_dir);

    rc = torture_change_dir(test_state->cwd);
    assert_int_equal(rc, 0);

    rc = torture_rmdirs(test_state->temp_dir);
    assert_int_equal(rc, 0);

    SAFE_FREE(test_state->temp_dir);
    SAFE_FREE(test_state->cwd);
    SAFE_FREE(test_state);

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
    assert_null(type_c);

    type_c = ssh_key_type_to_char(42);
    assert_null(type_c);
}

static void torture_pki_signature(void **state)
{
    ssh_signature sig;

    (void) state; /* unused */

    sig = ssh_signature_new();
    assert_non_null(sig);

    ssh_signature_free(sig);
}

struct key_attrs {
    int sign;
    int verify;
    const char *type_c;
    int size_arg;
    int sig_length;
    const char *sig_type_c;
};

struct key_attrs key_attrs_list[] = {
    {0, 0, "", 0, 0, ""},                                        /* UNKNOWN */
#ifdef HAVE_DSA
    {1, 1, "ssh-dss", 1024, 20, "ssh-dss" },                     /* DSS */
#else
    {0, 0, "", 0, 0, ""},                                        /* DSS */
#endif
    {1, 1, "ssh-rsa", 2048, 20, "ssh-rsa"},                      /* RSA */
    {0, 0, "", 0, 0, ""},                                        /* RSA1 */
    {0, 0, "", 0, 0, ""},                                        /* ECDSA */
    {1, 1, "ssh-ed25519", 0, 33, "ssh-ed25519"},                 /* ED25519 */
#ifdef HAVE_DSA
    {0, 1, "", 0, 0, ""},                                        /* DSS CERT */
#else
    {0, 0, "", 0, 0, ""},                                        /* DSS CERT */
#endif
    {0, 1, "", 0, 0, ""},                                        /* RSA CERT */
    {1, 1, "ecdsa-sha2-nistp256", 0, 64, "ecdsa-sha2-nistp256"}, /* ECDSA P256 */
    {1, 1, "ecdsa-sha2-nistp384", 0, 64, "ecdsa-sha2-nistp384"}, /* ECDSA P384 */
    {1, 1, "ecdsa-sha2-nistp521", 0, 64, "ecdsa-sha2-nistp521"}, /* ECDSA P521 */
    {0, 1, "", 0, 0, ""},                                        /* ECDSA P256 CERT */
    {0, 1, "", 0, 0, ""},                                        /* ECDSA P384 CERT */
    {0, 1, "", 0, 0, ""},                                        /* ECDSA P521 CERT */
    {0, 1, "", 0, 0, ""},                                        /* ED25519 CERT */
};

/* Maps to enum ssh_digest_e */
const char *hash_signatures[] = {
    "", /* Not used here */
    "ssh-rsa",
    "rsa-sha2-256",
    "", /* Not used; there is no rsa-sha2-384 */
    "rsa-sha2-512",
};

/* Maps to enum ssh_digest_e */
int hash_lengths[] = {
    0, /* Not used here */
    20,
    32,
    48, /* Not used; there is no rsa-sha2-384 */
    64,
};

/* This tests all the base types and their signatures against each other */
static void torture_pki_verify_mismatch(void **state)
{
    int rc;
    int verbosity = torture_libssh_verbosity();
    ssh_key key = NULL, verify_key = NULL;
    ssh_signature sign = NULL, import_sig = NULL, new_sig = NULL;
    ssh_string blob;
    ssh_session session = ssh_new();
    enum ssh_keytypes_e key_type, sig_type;
    enum ssh_digest_e hash;
    int hash_length;
    struct key_attrs skey_attrs, vkey_attrs;

    (void) state;

    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    for (sig_type = SSH_KEYTYPE_DSS;
         sig_type <= SSH_KEYTYPE_ED25519;
         sig_type++) {
        skey_attrs = key_attrs_list[sig_type];
        if (!skey_attrs.sign) {
            continue;
        }
        rc = ssh_pki_generate(sig_type, skey_attrs.size_arg, &key);
        assert_true(rc == SSH_OK);
        assert_non_null(key);
        assert_int_equal(key->type, sig_type);
        assert_string_equal(key->type_c, skey_attrs.type_c);

        for (hash = SSH_DIGEST_AUTO;
             hash <= SSH_DIGEST_SHA512;
             hash++) {
            hash_length = ((hash == SSH_DIGEST_AUTO) ?
                              skey_attrs.sig_length : hash_lengths[hash]);

            /* SHA384 is used only internaly for ECDSA. Skip it. */
            if (hash == SSH_DIGEST_SHA384) {
                continue;
            }

            SSH_LOG(SSH_LOG_TRACE, "Creating signature %d with hash %d",
                    sig_type, hash);

            /* Create a valid signature using this key */
            sign = pki_do_sign_hash(key, HASH, hash_length, hash);
            assert_non_null(sign);
            assert_int_equal(sign->type, key->type);
            if (hash == SSH_DIGEST_AUTO) {
                assert_string_equal(sign->type_c, key->type_c);
                assert_string_equal(sign->type_c, skey_attrs.sig_type_c);
            } else {
                assert_string_equal(sign->type_c, hash_signatures[hash]);
            }

            /* Create a signature blob that can be imported and verified */
            blob = pki_signature_to_blob(sign);
            assert_non_null(blob);

            /* Import and verify with current key
             * (this is not tested anywhere else yet) */
            import_sig = pki_signature_from_blob(key,
                                                 blob,
                                                 sig_type,
                                                 hash);
            assert_non_null(import_sig);
            assert_int_equal(import_sig->type, key->type);
            if (hash == SSH_DIGEST_AUTO) {
                assert_string_equal(import_sig->type_c, key->type_c);
                assert_string_equal(import_sig->type_c, skey_attrs.sig_type_c);
            } else {
                assert_string_equal(import_sig->type_c, hash_signatures[hash]);
            }

            /* Internal API: Should work */
            rc = pki_signature_verify(session,
                                      import_sig,
                                      key,
                                      HASH,
                                      hash_length);
            assert_true(rc == SSH_OK);

            for (key_type = SSH_KEYTYPE_DSS;
                 key_type <= SSH_KEYTYPE_ED25519_CERT01;
                 key_type++) {
                vkey_attrs = key_attrs_list[key_type];
                if (!vkey_attrs.verify) {
                    continue;
                }
                SSH_LOG(SSH_LOG_TRACE, "Trying key %d with signature %d",
                        key_type, sig_type);

                if (is_cert_type(key_type)) {
                    torture_write_file("libssh_testkey-cert.pub",
                       torture_get_testkey_pub(key_type));
                    rc = ssh_pki_import_cert_file("libssh_testkey-cert.pub", &verify_key);
                } else {
                    rc = ssh_pki_generate(key_type, vkey_attrs.size_arg, &verify_key);
                }
                assert_true(rc == SSH_OK);
                assert_non_null(verify_key);

                /* Should gracefully fail, but not crash */
                rc = pki_signature_verify(session,
                                          sign,
                                          verify_key,
                                          HASH,
                                          hash_length);
                assert_true(rc != SSH_OK);

                /* Try the same with the imported signature */
                rc = pki_signature_verify(session,
                                          import_sig,
                                          verify_key,
                                          HASH,
                                          hash_length);
                assert_true(rc != SSH_OK);

                /* Try to import the signature blob with different key */
                new_sig = pki_signature_from_blob(verify_key,
                                                  blob,
                                                  sig_type,
                                                  import_sig->hash_type);
                if (ssh_key_type_plain(key_type) == sig_type) {
                    /* Importing with the same key type should work */
                    assert_non_null(new_sig);
                    assert_int_equal(new_sig->type, key->type);
                    if (ssh_key_type_plain(key_type) == SSH_KEYTYPE_RSA &&
                    new_sig->hash_type != SSH_DIGEST_AUTO) {
                        assert_string_equal(new_sig->type_c, hash_signatures[new_sig->hash_type]);
                    } else {
                        assert_string_equal(new_sig->type_c, key->type_c);
                        assert_string_equal(new_sig->type_c, skey_attrs.sig_type_c);
                    }
                    /* The verification should not work */
                    rc = pki_signature_verify(session,
                                              new_sig,
                                              verify_key,
                                              HASH,
                                              hash_length);
                    assert_true(rc != SSH_OK);

                    ssh_signature_free(new_sig);
                } else {
                    assert_null(new_sig);
                }
                SSH_KEY_FREE(verify_key);
            }

            ssh_string_free(blob);
            ssh_signature_free(sign);
            ssh_signature_free(import_sig);

            /* XXX Test all the hash versions only with RSA. */
            if (sig_type != SSH_KEYTYPE_RSA || hash == SSH_DIGEST_SHA512) {
                break;
            }
        }

        SSH_KEY_FREE(key);
        key = NULL;
    }

    ssh_free(session);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_pki_keytype),
        cmocka_unit_test(torture_pki_signature),
        cmocka_unit_test_setup_teardown(torture_pki_verify_mismatch,
                                        setup_cert_dir,
                                        teardown_cert_dir),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
