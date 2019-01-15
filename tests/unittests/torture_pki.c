#include "config.h"

#define LIBSSH_STATIC

#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "torture_pki.h"
#include "pki.c"


const unsigned char HASH[] = "1234567890123456789012345678901234567890"
                             "123456789012345678901234";

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

/* Maps to enum ssh_keytypes_e */
const char *key_types[] = {
    "", /* UNKNOWN */
    "ssh-dss",
    "ssh-rsa",
    "",/* RSA1 */
    "ecdsa-sha2-nistp521",
    "ssh-ed25519",
};

/* Maps to enum ssh_keytypes_e */
const int key_sizes[] = {
    0, /* UNKNOWN */
    1024,
    2048,
    0, /* RSA1 */
    521,
    0,
};

/* Maps to enum ssh_keytypes_e */
const int sig_lengths[]  = {
    0, /* UNKNOWN */
    20,
    20,
    0, /* RSA1 */
    64,
    33,
};

/* Maps to enum ssh_keytypes_e */
const char *signature_types[] = {
    "", /* UNKNOWN */
    "ssh-dss",
    "ssh-rsa",
    "",/* RSA1 */
    "ecdsa-sha2-nistp521",
    "ssh-ed25519",
};

/* Maps to enum ssh_digest_e */
const char *hash_signatures[] = {
    "", /* Not used here */
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
};

/* Maps to enum ssh_digest_e */
int hash_lengths[] = {
    0, /* Not used here */
    20,
    32,
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
    enum ssh_keytypes_e key_type, sig_type, first_key;
    enum ssh_digest_e hash;
    int hash_length;

    (void) state;

    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

#ifdef HAVE_DSA
    first_key = SSH_KEYTYPE_DSS;
#else
    first_key = SSH_KEYTYPE_RSA;
#endif /* HAVE_DSA */

    for (sig_type = first_key;
         sig_type <= SSH_KEYTYPE_ED25519;
         sig_type++) {
        if (sig_type == SSH_KEYTYPE_RSA1) {
            continue;
        }
        rc = ssh_pki_generate(sig_type, key_sizes[sig_type], &key);
        assert_true(rc == SSH_OK);
        assert_non_null(key);
        assert_int_equal(key->type, sig_type);
        assert_string_equal(key->type_c, key_types[sig_type]);

        for (hash = SSH_DIGEST_AUTO;
             hash <= SSH_DIGEST_SHA512;
             hash++) {
            hash_length = ((hash == SSH_DIGEST_AUTO) ?
                              sig_lengths[sig_type] : hash_lengths[hash]);

            SSH_LOG(SSH_LOG_TRACE, "Creating signature %d with hash %d",
                    sig_type, hash);

            /* Create a valid signature using this key */
            sign = pki_do_sign_hash(key, HASH, hash_length, hash);
            assert_non_null(sign);
            assert_int_equal(sign->type, key->type);
            if (hash == SSH_DIGEST_AUTO) {
                assert_string_equal(sign->type_c, key->type_c);
                assert_string_equal(sign->type_c, signature_types[sig_type]);
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
                assert_string_equal(import_sig->type_c, signature_types[sig_type]);
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

            for (key_type = first_key;
                 key_type <= SSH_KEYTYPE_ED25519;
                 key_type++) {
                if (key_type == SSH_KEYTYPE_RSA1) {
                    continue;
                }
                SSH_LOG(SSH_LOG_TRACE, "Trying key %d with signature %d",
                        key_type, sig_type);

                rc = ssh_pki_generate(key_type, key_sizes[key_type], &verify_key);
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
                if (sig_type != key_type) {
                    assert_null(new_sig);
                } else {
                    /* Importing with the same key type should work */
                    assert_non_null(new_sig);
                    assert_int_equal(new_sig->type, key->type);
                    if (key_type == SSH_KEYTYPE_RSA && new_sig->hash_type != SSH_DIGEST_AUTO) {
                        assert_string_equal(new_sig->type_c, hash_signatures[new_sig->hash_type]);
                    } else {
                        assert_string_equal(new_sig->type_c, key->type_c);
                        assert_string_equal(new_sig->type_c, signature_types[sig_type]);
                    }
                    /* The verification should not work */
                    rc = pki_signature_verify(session,
                                              new_sig,
                                              verify_key,
                                              HASH,
                                              hash_length);
                    assert_true(rc != SSH_OK);

                    ssh_signature_free(new_sig);
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
        cmocka_unit_test(torture_pki_verify_mismatch),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
