#include "config.h"

#define LIBSSH_STATIC

#ifndef _WIN32
#define _POSIX_PTHREAD_SEMANTICS
# include <pwd.h>
#endif
#include <sys/stat.h>

#include "torture.h"
#include "torture_key.h"
#include <errno.h>
#include <libssh/config.h>
#include <libssh/misc.h>
#include <libssh/options.h>
#include <libssh/pki.h>
#include <libssh/pki_priv.h>
#include <libssh/session.h>

#ifdef _WIN32
#include <netioapi.h>
#else
#include <net/if.h>
#endif

#ifdef WITH_SERVER
#include <libssh/bind.h>
#define LIBSSH_CUSTOM_BIND_CONFIG_FILE "my_bind_config"
#endif
#define LIBSSH_RSA_TESTKEY        "libssh_testkey.id_rsa"
#define LIBSSH_ED25519_TESTKEY    "libssh_testkey.id_ed25519"
#ifdef HAVE_ECC
#define LIBSSH_ECDSA_521_TESTKEY  "libssh_testkey.id_ecdsa521"
#endif

static int setup(void **state)
{
    ssh_session session;
    int verbosity;

    session = ssh_new();

    verbosity = torture_libssh_verbosity();
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    session->client = 1;

    *state = session;

    return 0;
}

static int teardown(void **state)
{
    ssh_free(*state);

    return 0;
}

static void torture_options_set_host(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == 0);
    assert_non_null(session->opts.host);
    assert_string_equal(session->opts.host, "localhost");
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "localhost");

    /* IPv4 address */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "127.1.1.1");
    assert_true(rc == 0);
    assert_non_null(session->opts.host);
    assert_string_equal(session->opts.host, "127.1.1.1");
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "127.1.1.1");
    assert_null(session->opts.username);

    /* IPv6 address */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "::1");
    assert_true(rc == 0);
    assert_non_null(session->opts.host);
    assert_string_equal(session->opts.host, "::1");
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "::1");
    assert_null(session->opts.username);

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "guru@meditation");
    assert_true(rc == 0);
    assert_non_null(session->opts.host);
    assert_string_equal(session->opts.host, "meditation");
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "meditation");
    assert_non_null(session->opts.username);
    assert_string_equal(session->opts.username, "guru");

    /* more @ in uri is OK -- it should go to the username */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "at@login@hostname");
    assert_true(rc == 0);
    assert_non_null(session->opts.host);
    assert_string_equal(session->opts.host, "hostname");
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "hostname");
    assert_non_null(session->opts.username);
    assert_string_equal(session->opts.username, "at@login");

    /* disallow metacharacters in the username */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "shallN()tP4ss -@hostname");
    assert_string_equal(ssh_get_error(session),
                        "Invalid argument in ssh_options_set");
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);

    /* IPv6 hostnames should work without square braces */
    SAFE_FREE(session->opts.username);
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HOST,
                         "fd4d:5449:7400:111:626d:3cff:fedf:4d39");
    assert_return_code(rc, errno);
    assert_non_null(session->opts.host);
    assert_string_equal(session->opts.host,
                        "fd4d:5449:7400:111:626d:3cff:fedf:4d39");
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost,
                        "fd4d:5449:7400:111:626d:3cff:fedf:4d39");
    assert_null(session->opts.username);

    /* IPv6 hostnames should work also with square braces */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HOST,
                         "[fd4d:5449:7400:111:626d:3cff:fedf:4d39]");
    assert_return_code(rc, errno);
    assert_non_null(session->opts.host);
    assert_string_equal(session->opts.host,
                        "fd4d:5449:7400:111:626d:3cff:fedf:4d39");
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost,
                        "fd4d:5449:7400:111:626d:3cff:fedf:4d39");
    assert_null(session->opts.username);

    /* user@IPv6%interface
     * Use dynamic interface name for cross-platform portability */
    {
        char interf[IF_NAMESIZE] = {0};
        char ipv6_zone[128] = {0};
        char expected_host[128] = {0};

        if_indextoname(1, interf);
        assert_non_null(interf);
        snprintf(ipv6_zone, sizeof(ipv6_zone), "user@fe80::1%%%s", interf);
        snprintf(expected_host, sizeof(expected_host), "fe80::1%%%s", interf);

        rc = ssh_options_set(session, SSH_OPTIONS_HOST, ipv6_zone);
        assert_return_code(rc, errno);
        assert_non_null(session->opts.host);
        assert_string_equal(session->opts.host, expected_host);
        assert_non_null(session->opts.originalhost);
        assert_string_equal(session->opts.originalhost, expected_host);
        assert_string_equal(session->opts.username, "user");
    }

    /* IDN need to be in punycode format */
    SAFE_FREE(session->opts.username);
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "xn--bcher-kva.tld");
    assert_return_code(rc, errno);
    assert_non_null(session->opts.host);
    assert_string_equal(session->opts.host, "xn--bcher-kva.tld");
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "xn--bcher-kva.tld");
    assert_null(session->opts.username);

    /* IDN in UTF-8 is accepted but not as a valid hostname,
     * only originalhost is set */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "bücher.tld");
    assert_return_code(rc, errno);
    assert_null(session->opts.host);
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "bücher.tld");

    /* Config alias '%' rejected by RFC1035, only originalhost is set */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "%customer1");
    assert_return_code(rc, errno);
    assert_null(session->opts.host);
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "%customer1");

    /* user@alias '_' rejected by RFC1035, alias stored in originalhost */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "admin@customer_1");
    assert_return_code(rc, errno);
    assert_null(session->opts.host);
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "customer_1");
    assert_string_equal(session->opts.username, "admin");

    /* Shell metacharacters and leading dash rejected.
     * Verify failure cases do not update session options. */
    SAFE_FREE(session->opts.username);
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "host;rm -rf /");
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);
    assert_null(session->opts.host);
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "customer_1");
    assert_null(session->opts.username);

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "-leading-dash");
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);
    assert_null(session->opts.host);
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "customer_1");
    assert_null(session->opts.username);

    /* Empty user or host rejected */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "@hostname");
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);
    assert_null(session->opts.host);
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "customer_1");
    assert_null(session->opts.username);

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "user@");
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);
    assert_null(session->opts.host);
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "customer_1");
    assert_null(session->opts.username);

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "");
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);
    assert_null(session->opts.host);
    assert_non_null(session->opts.originalhost);
    assert_string_equal(session->opts.originalhost, "customer_1");
    assert_null(session->opts.username);

    /* Implicit hostname lowercasing */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "UPPERCASE-HOST");
    assert_return_code(rc, errno);
    rc = ssh_options_apply(session);
    assert_return_code(rc, errno);
    assert_string_equal(session->opts.host, "uppercase-host");
}

static void torture_options_set_ciphers(void **state)
{
    ssh_session session = *state;
    int rc;

    /* Test known ciphers */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_CIPHERS_C_S,
                         "aes128-ctr,aes192-ctr,aes256-ctr");
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.wanted_methods[SSH_CRYPT_C_S]);
    if (ssh_fips_mode()) {
        assert_string_equal(session->opts.wanted_methods[SSH_CRYPT_C_S],
                            "aes128-ctr,aes256-ctr");
    } else {
        assert_string_equal(session->opts.wanted_methods[SSH_CRYPT_C_S],
                            "aes128-ctr,aes192-ctr,aes256-ctr");
    }

    /* Test one unknown cipher */
    rc = ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S,
                         "aes128-ctr,unknown-crap@example.com,aes256-ctr");
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.wanted_methods[SSH_CRYPT_C_S]);
    assert_string_equal(session->opts.wanted_methods[SSH_CRYPT_C_S],
                        "aes128-ctr,aes256-ctr");

    /* Test all unknown ciphers */
    rc = ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S,
                         "unknown-crap@example.com,more-crap@example.com");
    assert_false(rc == 0);
}

static void torture_options_get_ciphers(void **state)
{
    ssh_session session = *state;
    int rc;
    char *value = NULL;

    /* Test defaults returned */
    rc = ssh_options_get(session, SSH_OPTIONS_CIPHERS_C_S, &value);
    assert_ssh_return_code(session, rc);
    assert_non_null(value);
    if (ssh_fips_mode()) {
        assert_string_equal(value,
                            "aes256-gcm@openssh.com,"
                            "aes256-ctr,"
                            "aes256-cbc,"
                            "aes128-gcm@openssh.com,"
                            "aes128-ctr,"
                            "aes128-cbc");
    } else {
        assert_string_equal(value,
                            "chacha20-poly1305@openssh.com,"
                            "aes256-gcm@openssh.com,"
                            "aes128-gcm@openssh.com,"
                            "aes256-ctr,"
                            "aes192-ctr,"
                            "aes128-ctr");
    }
    ssh_string_free_char(value);

    /* Test explicit ciphers */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_CIPHERS_C_S,
                         "aes128-ctr,aes192-ctr,aes256-ctr");
    assert_ssh_return_code(session, rc);

    value = NULL;
    rc = ssh_options_get(session, SSH_OPTIONS_CIPHERS_C_S, &value);
    assert_ssh_return_code(session, rc);
    assert_non_null(value);
    if (ssh_fips_mode()) {
        assert_string_equal(value, "aes128-ctr,aes256-ctr");
    } else {
        assert_string_equal(value, "aes128-ctr,aes192-ctr,aes256-ctr");
    }
    ssh_string_free_char(value);
}

static void torture_options_set_key_exchange(void **state)
{
    ssh_session session = *state;
    int rc;

    /* Test known kexes */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_KEY_EXCHANGE,
                         "sntrup761x25519-sha512,"
                         "sntrup761x25519-sha512@openssh.com,"
                         "curve25519-sha256,curve25519-sha256@libssh.org,"
                         "ecdh-sha2-nistp256,diffie-hellman-group16-sha512,"
                         "diffie-hellman-group18-sha512,"
                         "diffie-hellman-group14-sha256,"
                         "diffie-hellman-group14-sha1");
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.wanted_methods[SSH_KEX]);
    if (ssh_fips_mode()) {
        assert_string_equal(session->opts.wanted_methods[SSH_KEX],
                            "ecdh-sha2-nistp256,diffie-hellman-group16-sha512,"
                            "diffie-hellman-group18-sha512,"
                            "diffie-hellman-group14-sha256");
    } else {
        assert_string_equal(session->opts.wanted_methods[SSH_KEX],
                            "sntrup761x25519-sha512,"
                            "sntrup761x25519-sha512@openssh.com,"
                            "curve25519-sha256,curve25519-sha256@libssh.org,"
                            "ecdh-sha2-nistp256,diffie-hellman-group16-sha512,"
                            "diffie-hellman-group18-sha512,"
                            "diffie-hellman-group14-sha256,"
                            "diffie-hellman-group14-sha1");
    }

    /* Test one unknown kex */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_KEY_EXCHANGE,
                         "diffie-hellman-group16-sha512,"
                         "unknown-crap@example.com,"
                         "diffie-hellman-group18-sha512");
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.wanted_methods[SSH_KEX]);
    assert_string_equal(session->opts.wanted_methods[SSH_KEX],
                        "diffie-hellman-group16-sha512,"
                        "diffie-hellman-group18-sha512");

    /* Test all unknown kexes */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_KEY_EXCHANGE,
                         "unknown-crap@example.com,more-crap@example.com");
    assert_false(rc == 0);
}

static void torture_options_get_key_exchange(void **state)
{
    ssh_session session = *state;
    int rc;
    char *value = NULL;
    const char *exp_value = NULL;

    /* Test defaults returned */
    rc = ssh_options_get(session, SSH_OPTIONS_KEY_EXCHANGE, &value);
    assert_ssh_return_code(session, rc);
    assert_non_null(value);
    if (ssh_fips_mode()) {
        exp_value = "mlkem768nistp256-sha256,"
#ifdef HAVE_MLKEM1024
                    "mlkem1024nistp384-sha384,"
#endif
                    "ecdh-sha2-nistp256,"
                    "ecdh-sha2-nistp384,"
                    "ecdh-sha2-nistp521,"
                    "diffie-hellman-group-exchange-sha256,"
                    "diffie-hellman-group14-sha256,"
                    "diffie-hellman-group16-sha512,"
                    "diffie-hellman-group18-sha512";
    } else {
        exp_value = "mlkem768x25519-sha256,"
                    "mlkem768nistp256-sha256,"
#ifdef HAVE_MLKEM1024
                    "mlkem1024nistp384-sha384,"
#endif
                    "sntrup761x25519-sha512,"
                    "sntrup761x25519-sha512@openssh.com,"
                    "curve25519-sha256,curve25519-sha256@libssh.org,"
                    "ecdh-sha2-nistp256,ecdh-sha2-nistp384,"
                    "ecdh-sha2-nistp521,diffie-hellman-group18-sha512,"
                    "diffie-hellman-group16-sha512,"
                    "diffie-hellman-group-exchange-sha256,"
                    "diffie-hellman-group14-sha256";
    }
    assert_string_equal(value, exp_value);
    ssh_string_free_char(value);

    /* Test explicit kexes */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_KEY_EXCHANGE,
                         "curve25519-sha256,curve25519-sha256@libssh.org,"
                         "ecdh-sha2-nistp256,diffie-hellman-group16-sha512,"
                         "diffie-hellman-group18-sha512,"
                         "diffie-hellman-group14-sha256,"
                         "diffie-hellman-group14-sha1");
    assert_ssh_return_code(session, rc);

    value = NULL;
    rc = ssh_options_get(session, SSH_OPTIONS_KEY_EXCHANGE, &value);
    assert_ssh_return_code(session, rc);
    assert_non_null(value);
    if (ssh_fips_mode()) {
        assert_string_equal(value,
                            "ecdh-sha2-nistp256,diffie-hellman-group16-sha512,"
                            "diffie-hellman-group18-sha512,"
                            "diffie-hellman-group14-sha256");
    } else {
        assert_string_equal(value,
                            "curve25519-sha256,curve25519-sha256@libssh.org,"
                            "ecdh-sha2-nistp256,diffie-hellman-group16-sha512,"
                            "diffie-hellman-group18-sha512,"
                            "diffie-hellman-group14-sha256,"
                            "diffie-hellman-group14-sha1");
    }
    ssh_string_free_char(value);
}

static void torture_options_set_hostkey(void **state)
{
    ssh_session session = *state;
    int rc;

    /* Test known host keys */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HOSTKEYS,
                         "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.wanted_methods[SSH_HOSTKEYS]);
    if (ssh_fips_mode()) {
        assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                            "ecdsa-sha2-nistp384");
    } else {
        assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                            "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    }

    /* Test one unknown host key */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HOSTKEYS,
                         "ecdsa-sha2-nistp521,"
                         "unknown-crap@example.com,"
                         "rsa-sha2-256");
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.wanted_methods[SSH_HOSTKEYS]);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        "ecdsa-sha2-nistp521,"
                        "rsa-sha2-256");

    /* Test all unknown host keys */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HOSTKEYS,
                         "unknown-crap@example.com,more-crap@example.com");
    assert_false(rc == 0);
}

static void torture_options_get_hostkey(void **state)
{
    ssh_session session = *state;
    int rc;
    char *value = NULL;

    rc = ssh_options_get(session, SSH_OPTIONS_HOSTKEYS, &value);
    assert_ssh_return_code(session, rc);
    assert_non_null(value);
    if (ssh_fips_mode()) {
        assert_string_equal(value,
                            "ecdsa-sha2-nistp521-cert-v01@openssh.com,"
                            "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
                            "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
                            "rsa-sha2-512-cert-v01@openssh.com,"
                            "rsa-sha2-256-cert-v01@openssh.com,"
                            "ecdsa-sha2-nistp521,"
                            "ecdsa-sha2-nistp384,"
                            "ecdsa-sha2-nistp256,"
                            "rsa-sha2-512,"
                            "rsa-sha2-256");
    } else {
        assert_string_equal(value,
                            "ssh-ed25519-cert-v01@openssh.com,"
                            "ecdsa-sha2-nistp521-cert-v01@openssh.com,"
                            "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
                            "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
                            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,"
                            "rsa-sha2-512-cert-v01@openssh.com,"
                            "rsa-sha2-256-cert-v01@openssh.com,"
                            "ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,"
                            "ecdsa-sha2-nistp256,sk-ssh-ed25519@openssh.com,"
                            "sk-ecdsa-sha2-nistp256@openssh.com,"
                            "rsa-sha2-512,rsa-sha2-256");
    }
    ssh_string_free_char(value);

    /* Test explicit host keys */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HOSTKEYS,
                         "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    assert_ssh_return_code(session, rc);

    value = NULL;
    rc = ssh_options_get(session, SSH_OPTIONS_HOSTKEYS, &value);
    assert_ssh_return_code(session, rc);
    assert_non_null(value);
    if (ssh_fips_mode()) {
        assert_string_equal(value, "ecdsa-sha2-nistp384");
    } else {
        assert_string_equal(value, "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    }
    ssh_string_free_char(value);
}

static void torture_options_set_pubkey_accepted_types(void **state)
{
    ssh_session session = *state;
    int rc;
    enum ssh_digest_e type;

    /* Test known public key algorithms */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
                         "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.pubkey_accepted_types);
    if (ssh_fips_mode()) {
        assert_string_equal(session->opts.pubkey_accepted_types,
                            "ecdsa-sha2-nistp384");
    } else {
        assert_string_equal(session->opts.pubkey_accepted_types,
                            "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    }

    if (!ssh_fips_mode()) {
        /* Test one unknown public key algorithms */
        rc = ssh_options_set(session,
                             SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
                             "ssh-ed25519,unknown-crap@example.com,ssh-rsa");
        assert_ssh_return_code(session, rc);
        assert_non_null(session->opts.pubkey_accepted_types);
        assert_string_equal(session->opts.pubkey_accepted_types,
                            "ssh-ed25519,ssh-rsa");

        /* Test all unknown public key algorithms */
        rc = ssh_options_set(session,
                             SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
                             "unknown-crap@example.com,more-crap@example.com");
        assert_false(rc == 0);

        /* Test that the option affects the algorithm selection for RSA keys */
        /* simulate the SHA2 extension was negotiated */
        session->extensions = SSH_EXT_SIG_RSA_SHA256;

        /* previous configuration did not list the SHA2 extension algorithms, so
         * it should not be used */
        type = ssh_key_type_to_hash(session, SSH_KEYTYPE_RSA);
        assert_int_equal(type, SSH_DIGEST_SHA1);
    }

    /* now, lets allow the signature from SHA2 extension and expect
     * it to be used */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
                         "rsa-sha2-256,ssh-rsa");
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.pubkey_accepted_types);
    if (ssh_fips_mode()) {
        assert_string_equal(session->opts.pubkey_accepted_types,
                "rsa-sha2-256");
    } else {
        assert_string_equal(session->opts.pubkey_accepted_types,
                "rsa-sha2-256,ssh-rsa");
    }

    /* Test that the option affects the algorithm selection for RSA keys */
    /* simulate the SHA2 extension was negotiated */
    session->extensions = SSH_EXT_SIG_RSA_SHA256;

    type = ssh_key_type_to_hash(session, SSH_KEYTYPE_RSA);
    assert_int_equal(type, SSH_DIGEST_SHA256);
}

static void torture_options_get_pubkey_accepted_types(void **state)
{
    ssh_session session = *state;
    int rc;
    char *value = NULL;

    /* Test known public key algorithms */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
                         "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_get(session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, &value);
    assert_ssh_return_code(session, rc);
    assert_non_null(value);
    if (ssh_fips_mode()) {
        assert_string_equal(value, "ecdsa-sha2-nistp384");
    } else {
        assert_string_equal(value, "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    }
    ssh_string_free_char(value);
}


static void torture_options_set_macs(void **state)
{
    ssh_session session = *state;
    int rc;

    /* Test known MACs */
    rc = ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, "hmac-sha1");
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.wanted_methods[SSH_MAC_S_C]);
    assert_string_equal(session->opts.wanted_methods[SSH_MAC_S_C], "hmac-sha1");

    /* Test multiple known MACs */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HMAC_S_C,
                         "hmac-sha1-etm@openssh.com,"
                         "hmac-sha2-256-etm@openssh.com,"
                         "hmac-sha1,hmac-sha2-256");
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.wanted_methods[SSH_MAC_S_C]);
    assert_string_equal(session->opts.wanted_methods[SSH_MAC_S_C],
                        "hmac-sha1-etm@openssh.com,"
                        "hmac-sha2-256-etm@openssh.com,"
                        "hmac-sha1,hmac-sha2-256");

    /* Test unknown MACs */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HMAC_S_C,
                         "unknown-crap@example.com,hmac-sha1-etm@openssh.com,"
                         "unknown@example.com");
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.wanted_methods[SSH_MAC_S_C]);
    assert_string_equal(session->opts.wanted_methods[SSH_MAC_S_C],
                        "hmac-sha1-etm@openssh.com");

    /* Test all unknown MACs */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HMAC_S_C,
                         "unknown-crap@example.com");
    assert_false(rc == 0);
}

static void torture_options_get_macs(void **state)
{
    ssh_session session = *state;
    int rc;
    char *value = NULL;

    /* test defaults returned */
    rc = ssh_options_get(session, SSH_OPTIONS_HMAC_S_C, &value);
    assert_ssh_return_code(session, rc);
    assert_non_null(value);
    if (ssh_fips_mode()) {
        assert_string_equal(value,
                            "hmac-sha2-256-etm@openssh.com,"
                            "hmac-sha1-etm@openssh.com,"
                            "hmac-sha2-512-etm@openssh.com,"
                            "hmac-sha2-256,"
                            "hmac-sha1,"
                            "hmac-sha2-512");
    } else {
        assert_string_equal(value,
                            "hmac-sha2-256-etm@openssh.com,"
                            "hmac-sha2-512-etm@openssh.com,"
                            "hmac-sha2-256,"
                            "hmac-sha2-512");
    }
    ssh_string_free_char(value);

    /* Test known MACs */
    rc = ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, "hmac-sha1");
    assert_ssh_return_code(session, rc);

    value = NULL;
    rc = ssh_options_get(session, SSH_OPTIONS_HMAC_S_C, &value);
    assert_ssh_return_code(session, rc);
    assert_non_null(value);
    assert_string_equal(value, "hmac-sha1");
    ssh_string_free_char(value);
}

static void torture_options_set_compression(void **state)
{
    ssh_session session = *state;
    int rc;
    const char *known_value;
    const char *multiple;

#ifdef WITH_ZLIB
    if (ssh_fips_mode()) {
        known_value = "none";
        multiple = "none,squeeze";
    } else {
        known_value = "zlib";
        multiple = "zlib,squeeze";
    }
#else
    known_value = "none";
    multiple = "none,squeeze";
#endif

    /* Test known compression */
    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, known_value);
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.wanted_methods[SSH_COMP_S_C]);
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C],
                        known_value);

    /* Test multiple known compression */
    if (!ssh_fips_mode()) {
        rc = ssh_options_set(session,
                             SSH_OPTIONS_COMPRESSION_S_C,
                             "none,zlib@openssh.com");
        assert_ssh_return_code(session, rc);
        assert_non_null(session->opts.wanted_methods[SSH_COMP_S_C]);
#ifdef WITH_ZLIB
        assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C],
                            "none,zlib@openssh.com");
#else
        assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C], "none");
#endif
    }

    /* Test unknown compression */
    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, multiple);
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.wanted_methods[SSH_COMP_S_C]);
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C],
                        known_value);

    /* Test all unknown compression */
    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, "squeeze");
    assert_false(rc == 0);
}

static void torture_options_get_compression(void **state)
{
    ssh_session session = *state;
    int rc;
    char *value = NULL;
    const char *test_value = NULL;

#ifdef WITH_ZLIB
    if (ssh_fips_mode()) {
        test_value = "none";
    } else {
        test_value = "zlib@openssh.com";
    }
#else
    test_value = "none";
#endif

    /* test defaults returned */
    rc = ssh_options_get(session, SSH_OPTIONS_COMPRESSION_S_C, &value);
    assert_ssh_return_code(session, rc);
    assert_non_null(value);
#ifdef WITH_ZLIB
    assert_string_equal(value, "none,zlib@openssh.com");
#else
    assert_string_equal(value, "none");
#endif
    ssh_string_free_char(value);

    /* Test known compression */
    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, test_value);
    assert_ssh_return_code(session, rc);

    value = NULL;
    rc = ssh_options_get(session, SSH_OPTIONS_COMPRESSION_S_C, &value);
    assert_ssh_return_code(session, rc);
    assert_non_null(value);
    assert_string_equal(value, test_value);
    ssh_string_free_char(value);
}

static void torture_options_get_host(void **state)
{
    ssh_session session = *state;
    int rc;
    char* host = NULL;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == 0);
    assert_string_equal(session->opts.host, "localhost");

    assert_false(ssh_options_get(session, SSH_OPTIONS_HOST, &host));

    assert_string_equal(host, "localhost");
    ssh_string_free_char(host);

    /* When host is not yet resolved, falls back to originalhost */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "my_alias");
    assert_true(rc == 0);
    assert_null(session->opts.host);
    assert_non_null(session->opts.originalhost);

    assert_false(ssh_options_get(session, SSH_OPTIONS_HOST, &host));
    assert_string_equal(host, "my_alias");
    ssh_string_free_char(host);

    /* After config resolution, get returns resolved host, not originalhost */
    session->opts.host = strdup("192.168.1.1");
    assert_non_null(session->opts.host);

    assert_false(ssh_options_get(session, SSH_OPTIONS_HOST, &host));
    assert_string_equal(host, "192.168.1.1");
    ssh_string_free_char(host);
    /* originalhost is unchanged */
    assert_string_equal(session->opts.originalhost, "my_alias");
}

static void torture_options_set_port(void **state)
{
    ssh_session session = *state;
    int rc;
    unsigned int port = 42;

    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    assert_true(rc == 0);
    assert_true(session->opts.port == port);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT_STR, "23");
    assert_true(rc == 0);
    assert_true(session->opts.port == 23);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT_STR, "23abc");
    assert_true(rc == -1);
    assert_true(session->opts.port == 23);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT_STR, "five");
    assert_true(rc == -1);
    assert_true(session->opts.port == 23);

    port = 65535;
    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    assert_true(rc == 0);
    assert_true(session->opts.port == 65535);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT_STR, "65535");
    assert_true(rc == 0);
    assert_true(session->opts.port == 65535);

    port = 65536;
    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    assert_true(rc == -1);
    assert_true(session->opts.port == 65535);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT_STR, "65536");
    assert_true(rc == -1);
    assert_true(session->opts.port == 65535);

    port = 0;
    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    assert_true(rc == -1);
    assert_true(session->opts.port == 65535);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT_STR, "-1");
    assert_true(rc == -1);
    assert_true(session->opts.port == 65535);

    port = 70000;
    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    assert_true(rc == -1);
    assert_true(session->opts.port == 65535);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT_STR, "70000");
    assert_true(rc == -1);
    assert_true(session->opts.port == 65535);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT, NULL);
    assert_true(rc == -1);
}

static void torture_options_get_port(void **state)
{
    ssh_session session = *state;
    unsigned int given_port = 1234;
    unsigned int port_container;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &given_port);
    assert_true(rc == 0);
    rc = ssh_options_get_port(session, &port_container);
    assert_true(rc == 0);
    assert_int_equal(port_container, 1234);
}

static void torture_options_get_user(void **state)
{
    ssh_session session = *state;
    char *user = NULL;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_USER, "magicaltrevor");
    assert_int_equal(rc, SSH_OK);
    rc = ssh_options_get(session, SSH_OPTIONS_USER, &user);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(user);
    assert_string_equal(user, "magicaltrevor");
    ssh_string_free_char(user);
}

static void torture_options_set_fd(void **state)
{
    ssh_session session = *state;
    socket_t fd = 42;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_FD, &fd);
    assert_true(rc == 0);
    assert_true(session->opts.fd == fd);

    rc = ssh_options_set(session, SSH_OPTIONS_FD, NULL);
    assert_true(rc == SSH_ERROR);
    assert_true(session->opts.fd == SSH_INVALID_SOCKET);
}

static void torture_options_set_user(void **state)
{
    ssh_session session = *state;
    int rc;
#ifndef _WIN32
# ifndef NSS_BUFLEN_PASSWD
#  define NSS_BUFLEN_PASSWD 4096
# endif /* NSS_BUFLEN_PASSWD */
    struct passwd pwd;
    struct passwd *pwdbuf;
    char buf[NSS_BUFLEN_PASSWD];

    /* get local username */
    rc = getpwuid_r(getuid(), &pwd, buf, NSS_BUFLEN_PASSWD, &pwdbuf);
    assert_true(rc == 0);
#endif /* _WIN32 */

    rc = ssh_options_set(session, SSH_OPTIONS_USER, "&shallN()tP4ss");
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);

    rc = ssh_options_set(session, SSH_OPTIONS_USER, "guru");
    assert_true(rc == 0);
    assert_string_equal(session->opts.username, "guru");


    rc = ssh_options_set(session, SSH_OPTIONS_USER, NULL);
    assert_true(rc == 0);

#ifndef _WIN32
    assert_string_equal(session->opts.username, pwd.pw_name);
#endif
}

static void torture_options_set_identity(void **state)
{
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_ADD_IDENTITY, "identity1");
    assert_true(rc == 0);
    assert_string_equal(session->opts.identity_non_exp->root->data,
                        "identity1");

    rc = ssh_options_set(session, SSH_OPTIONS_IDENTITY, "identity2");
    assert_true(rc == 0);
    assert_string_equal(session->opts.identity_non_exp->root->data,
                        "identity2");
    assert_string_equal(session->opts.identity_non_exp->root->next->data,
                        "identity1");
}

static void torture_options_get_identity(void **state)
{
    ssh_session session = *state;
    char *identity = NULL;
    int rc;

    /* This adds an identity to the head of the list and returns */
    rc = ssh_options_set(session, SSH_OPTIONS_ADD_IDENTITY, "identity1");
    assert_true(rc == 0);
    rc = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &identity);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(identity);
    assert_string_equal(identity, "identity1");
    SAFE_FREE(identity);

    rc = ssh_options_set(session, SSH_OPTIONS_IDENTITY, "identity2");
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(session->opts.identity_non_exp->root->data,
                        "identity2");
    rc = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &identity);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(identity);
    assert_string_equal(identity, "identity2");
    ssh_string_free_char(identity);

    /* Iterate over all of the identities */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_IDENTITY, &identity);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(identity, "identity2");
    ssh_string_free_char(identity);

    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_IDENTITY, &identity);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(identity, "identity1");
    SAFE_FREE(identity);

    /* here are the default identities */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_IDENTITY, &identity);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(identity, "%d/.ssh/id_ed25519");
    ssh_string_free_char(identity);

    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_IDENTITY, &identity);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(identity, "%d/.ssh/id_ecdsa");
    ssh_string_free_char(identity);

    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_IDENTITY, &identity);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(identity, "%d/.ssh/id_rsa");
    ssh_string_free_char(identity);

#ifdef WITH_FIDO2
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_IDENTITY, &identity);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(identity, "%d/.ssh/id_ed25519_sk");
    ssh_string_free_char(identity);

    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_IDENTITY, &identity);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(identity, "%d/.ssh/id_ecdsa_sk");
    ssh_string_free_char(identity);
#endif /* WITH_FIDO2 */

    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_IDENTITY, &identity);
    assert_int_equal(rc, SSH_EOF);
}

static void torture_options_set_global_knownhosts(void **state)
{
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session,
                         SSH_OPTIONS_GLOBAL_KNOWNHOSTS,
                         "/etc/libssh/known_hosts");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.global_knownhosts,
                        "/etc/libssh/known_hosts");
}

static void torture_options_get_global_knownhosts(void **state)
{
    ssh_session session = *state;
    char *str = NULL;
    int rc;

    rc = ssh_options_set(session,
                         SSH_OPTIONS_GLOBAL_KNOWNHOSTS,
                         "/etc/libssh/known_hosts");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.global_knownhosts,
                        "/etc/libssh/known_hosts");


    rc = ssh_options_get(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, &str);
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.global_knownhosts,
                        "/etc/libssh/known_hosts");

    SSH_STRING_FREE_CHAR(str);
}

static void torture_options_set_knownhosts(void **state)
{
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session,
                         SSH_OPTIONS_KNOWNHOSTS,
                         "/home/libssh/.ssh/known_hosts");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.knownhosts,
                        "/home/libssh/.ssh/known_hosts");

    /* The NULL value should not crash the libssh */
    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, NULL);
    assert_ssh_return_code(session, rc);
    assert_null(session->opts.knownhosts);

    /* ssh_options_apply() should set the path to correct value */
    rc = ssh_options_apply(session);
    assert_ssh_return_code(session, rc);
    assert_non_null(session->opts.knownhosts);
}

static void torture_options_get_knownhosts(void **state)
{
    ssh_session session = *state;
    char *str = NULL;
    int rc;

    rc = ssh_options_set(session,
                         SSH_OPTIONS_KNOWNHOSTS,
                         "/home/libssh/.ssh/known_hosts");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.knownhosts,
                        "/home/libssh/.ssh/known_hosts");


    rc = ssh_options_get(session, SSH_OPTIONS_KNOWNHOSTS, &str);
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.knownhosts,
                        "/home/libssh/.ssh/known_hosts");

    SSH_STRING_FREE_CHAR(str);
}

static void torture_options_proxycommand(void **state) {
    ssh_session session = *state;
    int rc;

    /* Enable ProxyCommand */
    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "ssh -q -A -X -W %h:%p JUMPHOST");
    assert_int_equal(rc, 0);

    assert_string_equal(session->opts.ProxyCommand, "ssh -q -A -X -W %h:%p JUMPHOST");

    /* Disable ProxyCommand */
    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "none");
    assert_int_equal(rc, 0);

    assert_null(session->opts.ProxyCommand);
}

static void torture_options_control_master (void **state)
{
    ssh_session session = *state;
    int rc, val = SSH_CONTROL_MASTER_NO;

    rc = ssh_options_set(session,
                         SSH_OPTIONS_CONTROL_MASTER,
                         &val);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(session->opts.control_master, SSH_CONTROL_MASTER_NO);

    val = SSH_CONTROL_MASTER_AUTO;
    rc = ssh_options_set(session,
                         SSH_OPTIONS_CONTROL_MASTER,
                         &val);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(session->opts.control_master, SSH_CONTROL_MASTER_AUTO);

    val = SSH_CONTROL_MASTER_YES;
    rc = ssh_options_set(session,
                         SSH_OPTIONS_CONTROL_MASTER,
                         &val);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(session->opts.control_master, SSH_CONTROL_MASTER_YES);

    val = SSH_CONTROL_MASTER_ASK;
    rc = ssh_options_set(session,
                         SSH_OPTIONS_CONTROL_MASTER,
                         &val);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(session->opts.control_master, SSH_CONTROL_MASTER_ASK);

    val = SSH_CONTROL_MASTER_AUTOASK;
    rc = ssh_options_set(session,
                         SSH_OPTIONS_CONTROL_MASTER,
                         &val);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(session->opts.control_master, SSH_CONTROL_MASTER_AUTOASK);

    val = 255;
    rc = ssh_options_set(session,
                         SSH_OPTIONS_CONTROL_MASTER,
                         &val);
    assert_int_equal(rc, SSH_ERROR);
}

static void torture_options_control_path(void **state)
{
    ssh_session session = *state;
    char *str = NULL;
    int rc;

    /* Set Control Path */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_CONTROL_PATH,
                         "/tmp/ssh-%r@%h:%p");
    assert_int_equal(rc, 0);

    assert_string_equal(session->opts.control_path, "/tmp/ssh-%r@%h:%p");

    rc = ssh_options_get(session, SSH_OPTIONS_CONTROL_PATH, &str);
    assert_int_equal(rc, 0);
    assert_string_equal(str, "/tmp/ssh-%r@%h:%p");

    /* Disable Multiplexing */
    rc = ssh_options_set(session, SSH_OPTIONS_CONTROL_PATH, "none");
    assert_int_equal(rc, 0);

    assert_null(session->opts.control_path);
    SSH_STRING_FREE_CHAR(str);
}

static void torture_options_config_host(void **state)
{
    ssh_session session = *state;
    FILE *config = NULL;
    int rv;

    /* create a new config file */
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Host testhost1\nPort 42\n"
          "Host testhost2,testhost3\nPort 43\n"
          "Host testhost4 testhost5\nPort 44\n",
          config);
    fclose(config);

    ssh_options_set(session, SSH_OPTIONS_HOST, "testhost1");
    ssh_options_parse_config(session, "test_config");

    assert_int_equal(session->opts.port, 42);

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "testhost2");
    ssh_options_parse_config(session, "test_config");
    assert_int_equal(session->opts.port, 43);

    session->opts.port = 0;

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "testhost3");
    ssh_options_parse_config(session, "test_config");
    assert_int_equal(session->opts.port, 43);

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "testhost4");
    ssh_options_parse_config(session, "test_config");
    assert_int_equal(session->opts.port, 44);

    session->opts.port = 0;

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "testhost5");
    ssh_options_parse_config(session, "test_config");
    assert_int_equal(session->opts.port, 44);

    /* ssh_options_parse_config rejects when originalhost is NULL */
    SAFE_FREE(session->opts.host);
    SAFE_FREE(session->opts.originalhost);
    rv = ssh_options_parse_config(session, "test_config");
    assert_int_equal(rv, -1);

    /* Config Hostname with invalid hostname: verify stale host not leaked */
    torture_write_file("test_config", "Host 192.168.1.1\nHostname my_alias\n");

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "192.168.1.1");
    assert_string_equal(session->opts.host, "192.168.1.1");
    assert_string_equal(session->opts.originalhost, "192.168.1.1");
    rv = ssh_options_parse_config(session, "test_config");
    assert_int_equal(rv, 0);
    assert_null(session->opts.host);
    assert_string_equal(session->opts.originalhost, "192.168.1.1");

    /* Calling ssh_options_set(HOST) twice: verify stale host not leaked */
    ssh_options_set(session, SSH_OPTIONS_HOST, "real.server.com");
    assert_string_equal(session->opts.host, "real.server.com");
    assert_string_equal(session->opts.originalhost, "real.server.com");

    ssh_options_set(session, SSH_OPTIONS_HOST, "my_alias");
    assert_null(session->opts.host);
    assert_string_equal(session->opts.originalhost, "my_alias");

    unlink("test_config");
}

static void torture_options_config_match(void **state)
{
    ssh_session session = *state;
    char *localuser = NULL;
    FILE *config = NULL;
    int rv;

    /* Required for options_parse_config() */
    ssh_options_set(session, SSH_OPTIONS_HOST, "testhost1");

    /* The Match keyword requires argument */
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code_equal(session, rv, SSH_OK);

    /* The Match all keyword needs to be the only one (start) */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match all host local\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code_equal(session, rv, SSH_ERROR);

    /* The Match all keyword needs to be the only one (end) */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match host local all\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code_equal(session, rv, SSH_ERROR);

    /* The Match host keyword requires an argument */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match host\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code_equal(session, rv, SSH_ERROR);

    /* The Match user keyword requires an argument */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match user\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code_equal(session, rv, SSH_ERROR);

    /* The Match version keyword requires an argument */
    torture_reset_config(session);
    torture_write_file("test_config", "Match version\n");
    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code_equal(session, rv, SSH_ERROR);

    /* The Match tagged keyword requires an argument */
    torture_reset_config(session);
    torture_write_file("test_config", "Match tagged\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code_equal(session, rv, SSH_ERROR);

    /* The Tag keyword requires an argument */
    torture_reset_config(session);
    torture_write_file("test_config", "Tag\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code_equal(session, rv, SSH_ERROR);

    /* The Match canonical keyword is the same as match all */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match canonical\n"
          "\tPort 33\n"
          "Match all\n"
          "\tPort 34\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code_equal(session, rv, SSH_OK);
    assert_int_equal(session->opts.port, 33);

    session->opts.port = 0;

    /* The Match originalhost keyword is ignored */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match originalhost origin\n"
          "\tPort 33\n"
          "Match all\n"
          "\tPort 34\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 34);

    session->opts.port = 0;

    /* The Match localuser keyword */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match localuser ", config);
    localuser = ssh_get_local_username();
    assert_non_null(localuser);
    fputs(localuser, config);
    ssh_string_free_char(localuser);
    fputs("\n"
          "\tPort 33\n"
          "Match all\n"
          "\tPort 34\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);

    session->opts.port = 0;

    /* The Match version keyword */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Match version libssh_*\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);

    session->opts.port = 0;

    /* A non-matching Match version keyword falls through */
    torture_reset_config(session);
    torture_write_file(
        "test_config",
        "Match version definitely-not-the-current-libssh-version\n"
        "\tPort 33\n"
        "Match all\n"
        "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 34);

    session->opts.port = 0;

    /* The negated Match version keyword */
    torture_reset_config(session);
    torture_write_file(
        "test_config",
        "Match !version definitely-not-the-current-libssh-version\n"
        "\tPort 33\n"
        "Match all\n"
        "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);

    session->opts.port = 0;

    /* The Match tagged keyword */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Tag jumped\n"
                       "Match tagged jump*\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);
    assert_string_equal(session->opts.tag, "jumped");

    session->opts.port = 0;

    /* The Match tagged=pattern syntax */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Tag jumped\n"
                       "Match tagged=jump*\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);
    assert_string_equal(session->opts.tag, "jumped");

    session->opts.port = 0;

    /* The Match tagged=\"pattern with spaces\" syntax */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Tag \"tag name\"\n"
                       "Match tagged=\"tag name\"\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);
    assert_string_equal(session->opts.tag, "tag name");

    session->opts.port = 0;

    /* The Match tagged=pattern\\ with\\ spaces syntax */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Tag \"tag name\"\n"
                       "Match tagged=tag\\ name\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);
    assert_string_equal(session->opts.tag, "tag name");

    session->opts.port = 0;

    /* A config Tag overrides a preexisting session tag */
    torture_reset_config(session);
    session->opts.tag = strdup("preset-tag");
    assert_non_null(session->opts.tag);
    torture_write_file("test_config",
                       "Tag config-tag\n"
                       "Match tagged config*\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);
    assert_string_equal(session->opts.tag, "config-tag");

    session->opts.port = 0;

    /* A non-matching Match tagged keyword falls through */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Tag jumped\n"
                       "Match tagged other\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 34);
    assert_string_equal(session->opts.tag, "jumped");

    session->opts.port = 0;

    /* The negated Match tagged keyword */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Tag jumped\n"
                       "Match !tagged other\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);
    assert_string_equal(session->opts.tag, "jumped");

    session->opts.port = 0;

    /* Match tagged does not match when no Tag was set */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Match tagged jumped\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 34);
    assert_null(session->opts.tag);

    session->opts.port = 0;

    /* An empty Match tagged= matches an unset tag */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Match tagged=\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);
    assert_null(session->opts.tag);

    session->opts.port = 0;

    /* An empty Match tagged "" matches an unset tag */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Match tagged \"\"\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);
    assert_null(session->opts.tag);

    session->opts.port = 0;

    /* Unterminated quotes in Match tagged= are rejected */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Tag \"tag name\"\n"
                       "Match tagged=\"unterminated\n"
                       "\tPort 33\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code_equal(session, rv, SSH_ERROR);

    session->opts.port = 0;

    /* The first Tag directive wins */
    torture_reset_config(session);
    torture_write_file("test_config",
                       "Tag first\n"
                       "Tag second\n"
                       "Match tagged first\n"
                       "\tPort 33\n"
                       "Match all\n"
                       "\tPort 34\n");

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 33);
    assert_string_equal(session->opts.tag, "first");

    session->opts.port = 0;

    /* The Match exec keyword */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match exec true\n"
          "\tPort 33\n"
          "Match all\n"
          "\tPort 34\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
#ifndef WITH_EXEC
    /* The match exec is not supported on windows at this moment */
    assert_int_equal(session->opts.port, 34);
#else
    assert_int_equal(session->opts.port, 33);
#endif

    session->opts.port = 0;

    /* Commands containing whitespace characters must be quoted. */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match exec \"true 1\"\n"
          "\tPort 33\n"
          "Match all\n"
          "\tPort 34\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
#ifndef WITH_EXEC
    /* The match exec is not supported on windows at this moment */
    assert_int_equal(session->opts.port, 34);
#else
    assert_int_equal(session->opts.port, 33);
#endif

    session->opts.port = 0;

    unlink("test_config");
}

static void torture_options_config_match_multi(void **state)
{
    ssh_session session = *state;
    FILE *config = NULL;
    struct stat sb;
    int rv;

    /* Required for options_parse_config() */
    ssh_options_set(session, SSH_OPTIONS_HOST, "testhost1");

    /* Exec is not executed when it can not be matched */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match host wronghost exec \"touch test_config_wrong\"\n"
          "\tPort 33\n"
          "Match all\n"
          "\tPort 34\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 34);
    assert_int_equal(stat("test_config_wrong", &sb), -1);

    session->opts.port = 0;

    /* After matching exec, other conditions can be used */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match exec true host testhost1\n"
          "\tPort 33\n"
          "Match all\n"
          "\tPort 34\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
#ifndef WITH_EXEC
    /* The match exec is not supported on windows at this moment */
    assert_int_equal(session->opts.port, 34);
#else
    assert_int_equal(session->opts.port, 33);
#endif

    /* After matching exec, other conditions can be used */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match exec true host otherhost\n"
          "\tPort 33\n"
          "Match all\n"
          "\tPort 34\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 34);

    unlink("test_config");
}

static void torture_options_copy(void **state)
{
    ssh_session session = *state, new = NULL;
    struct ssh_iterator *it = NULL, *it2 = NULL;
    FILE *config = NULL;
    int i, level = 9;
    int rv;

    /* Required for options_parse_config() */
    ssh_options_set(session, SSH_OPTIONS_HOST, "example");

    /* Impossible to set through the configuration */
    rv = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_LEVEL, &level);
    assert_ssh_return_code(session, rv);
    level = 1;
    rv = ssh_options_set(session, SSH_OPTIONS_NODELAY, &level);
    assert_ssh_return_code(session, rv);

    /* The Match keyword requires argument */
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("IdentityFile ~/.ssh/id_ecdsa\n"
          "IdentityFile ~/.ssh/my_rsa\n"
          "CertificateFile ~/.ssh/my_rsa-cert.pub\n"
          "CertificateFile ~/.ssh/id_ecdsa-cert.pub\n"
          "User tester\n"
          "Hostname example.com\n"
          "BindAddress 127.0.0.2\n"
          "GlobalKnownHostsFile /etc/ssh/known_hosts2\n"
          "UserKnownHostsFile ~/.ssh/known_hosts2\n"
          "KexAlgorithms curve25519-sha256,sntrup761x25519-sha512@openssh.com,ecdh-sha2-nistp521\n"
          "Ciphers aes256-ctr\n"
          "MACs hmac-sha2-256\n"
          "HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp521\n"
          "Compression yes\n"
          "PubkeyAcceptedAlgorithms ssh-ed25519,ecdsa-sha2-nistp521\n"
          "ProxyCommand nc 127.0.0.10 22\n"
          "ControlMaster ask\n"
          "ControlPath /tmp/ssh-%r@%h:%p\n"
          /* ops.custombanner */
          "ConnectTimeout 42\n"
          "Port 222\n"
          "StrictHostKeyChecking accept-new\n"
          "GSSAPIServerIdentity my.example.com\n"
          "GSSAPIClientIdentity home.sweet\n"
          "GSSAPIDelegateCredentials yes\n"
          "PubkeyAuthentication host-bound\n" /* sets flags */
          "GSSAPIAuthentication no\n"         /* sets flags */
          "AddressFamily inet6\n"
          "Tag copied-tag\n"
          "LocalForward 8080 web:80\n"
          "RemoteForward 9090 db:3306\n"
          "SendEnv LANG LC_*\n"
          "SendEnv TZ\n"
          "",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);

    rv = ssh_options_copy(session, &new);
    assert_ssh_return_code(session, rv);
    assert_non_null(new);

    /* Check the identities match */
    it = ssh_list_get_iterator(session->opts.identity_non_exp);
    assert_non_null(it);
    it2 = ssh_list_get_iterator(new->opts.identity_non_exp);
    assert_non_null(it2);
    while (it != NULL && it2 != NULL) {
        assert_string_equal(it->data, it2->data);
        it = it->next;
        it2 = it2->next;
    }
    assert_null(it);
    assert_null(it2);

    /* Check the certificates match */
    it = ssh_list_get_iterator(session->opts.certificate_non_exp);
    assert_non_null(it);
    it2 = ssh_list_get_iterator(new->opts.certificate_non_exp);
    assert_non_null(it2);
    while (it != NULL && it2 != NULL) {
        assert_string_equal(it->data, it2->data);
        it = it->next;
        it2 = it2->next;
    }
    assert_null(it);
    assert_null(it2);

    /* Check the local forwards match */
    it = ssh_list_get_iterator(session->opts.local_forward);
    assert_non_null(it);
    it2 = ssh_list_get_iterator(new->opts.local_forward);
    assert_non_null(it2);
    while (it != NULL && it2 != NULL) {
        assert_string_equal(it->data, it2->data);
        it = it->next;
        it2 = it2->next;
    }
    assert_null(it);
    assert_null(it2);

    /* Check the remote forwards match */
    it = ssh_list_get_iterator(session->opts.remote_forward);
    assert_non_null(it);
    it2 = ssh_list_get_iterator(new->opts.remote_forward);
    assert_non_null(it2);
    while (it != NULL && it2 != NULL) {
        assert_string_equal(ssh_iterator_value(const char *, it),
                            ssh_iterator_value(const char *, it2));
        it = it->next;
        it2 = it2->next;
    }
    assert_null(it);
    assert_null(it2);

    /* Check the send_env patterns match */
    it = ssh_list_get_iterator(session->opts.send_env);
    assert_non_null(it);
    it2 = ssh_list_get_iterator(new->opts.send_env);
    assert_non_null(it2);
    while (it != NULL && it2 != NULL) {
        assert_string_equal(it->data, it2->data);
        it = it->next;
        it2 = it2->next;
    }
    assert_null(it);
    assert_null(it2);

    assert_string_equal(session->opts.username, new->opts.username);
    assert_string_equal(session->opts.host, new->opts.host);
    assert_string_equal(session->opts.originalhost, new->opts.originalhost);
    assert_string_equal(session->opts.tag, new->opts.tag);
    assert_string_equal(session->opts.bindaddr, new->opts.bindaddr);
    assert_string_equal(session->opts.sshdir, new->opts.sshdir);
    assert_string_equal(session->opts.knownhosts, new->opts.knownhosts);
    assert_string_equal(session->opts.global_knownhosts,
                        new->opts.global_knownhosts);
    for (i = 0; i < SSH_KEX_METHODS; i++) {
        if (session->opts.wanted_methods[i] == NULL) {
            assert_null(new->opts.wanted_methods[i]);
        } else {
            assert_string_equal(session->opts.wanted_methods[i],
                                new->opts.wanted_methods[i]);
        }
    }
    assert_string_equal(session->opts.pubkey_accepted_types,
                        new->opts.pubkey_accepted_types);
    assert_string_equal(session->opts.ProxyCommand, new->opts.ProxyCommand);
    assert_null(new->opts.control_path);
    /* TODO custombanner */
    assert_int_equal(session->opts.timeout, new->opts.timeout);
    assert_int_equal(session->opts.timeout_usec, new->opts.timeout_usec);
    assert_int_equal(session->opts.port, new->opts.port);
    assert_int_equal(session->opts.control_master, new->opts.control_master);
    assert_int_equal(session->opts.StrictHostKeyChecking,
                     new->opts.StrictHostKeyChecking);
    assert_int_equal(session->opts.compressionlevel,
                     new->opts.compressionlevel);
    assert_string_equal(session->opts.gss_server_identity,
                        new->opts.gss_server_identity);
    assert_string_equal(session->opts.gss_client_identity,
                        new->opts.gss_client_identity);
    assert_int_equal(session->opts.gss_delegate_creds,
                     new->opts.gss_delegate_creds);
    assert_int_equal(session->opts.StrictHostKeyChecking,
                     SSH_STRICT_HOSTKEY_ACCEPT_NEW);
    assert_int_equal(new->opts.StrictHostKeyChecking,
                     SSH_STRICT_HOSTKEY_ACCEPT_NEW);
    assert_int_equal(session->opts.flags, new->opts.flags);
    assert_int_equal(session->opts.pubkey_auth, SSH_PUBKEY_AUTH_HOST_BOUND);
    assert_int_equal(new->opts.pubkey_auth, SSH_PUBKEY_AUTH_HOST_BOUND);
    assert_int_equal(session->opts.pubkey_auth, new->opts.pubkey_auth);
    assert_int_equal(session->opts.nodelay, new->opts.nodelay);
    assert_true(session->opts.config_processed == new->opts.config_processed);
    assert_memory_equal(session->opts.options_seen, new->opts.options_seen,
                        sizeof(session->opts.options_seen));
    assert_int_equal(session->opts.address_family, new->opts.address_family);

    ssh_free(new);

    /* test if ssh_options_apply was called before ssh_options_copy
     * the opts.identity list gets copied (percent expanded list) */
    rv = ssh_options_apply(session);
    assert_ssh_return_code(session, rv);

    rv = ssh_options_copy(session, &new);
    assert_ssh_return_code(session, rv);
    assert_non_null(new);

    it = ssh_list_get_iterator(session->opts.identity_non_exp);
    assert_null(it);
    it2 = ssh_list_get_iterator(new->opts.identity_non_exp);
    assert_null(it2);

    it = ssh_list_get_iterator(session->opts.identity);
    assert_non_null(it);
    it2 = ssh_list_get_iterator(new->opts.identity);
    assert_non_null(it2);
    while (it != NULL && it2 != NULL) {
        assert_string_equal(it->data, it2->data);
        it = it->next;
        it2 = it2->next;
    }
    assert_null(it);
    assert_null(it2);

    ssh_free(new);
}

static void torture_options_legacy_integer_values(void **state)
{
    ssh_session session = *state;
    int legacy_strict_value = 42;
    int negative_strict_value = -1;
    int zero_low_byte_strict_value = 256;
    int negative_zero_low_byte_strict_value = -256;
    int negative_pubkey_value = -1;
    int legacy_pubkey_value = 42;
    int disabled_pubkey_value = 0;
    int rc;

    /*
     * Legacy boolean-style integer inputs should continue to normalize to the
     * compatible multistate values accepted by ssh_options_set().
     */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_STRICTHOSTKEYCHECK,
                         &legacy_strict_value);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.StrictHostKeyChecking,
                     SSH_STRICT_HOSTKEY_YES);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_STRICTHOSTKEYCHECK,
                         &negative_strict_value);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.StrictHostKeyChecking,
                     SSH_STRICT_HOSTKEY_YES);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_STRICTHOSTKEYCHECK,
                         &zero_low_byte_strict_value);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.StrictHostKeyChecking,
                     SSH_STRICT_HOSTKEY_OFF);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_STRICTHOSTKEYCHECK,
                         &negative_zero_low_byte_strict_value);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.StrictHostKeyChecking,
                     SSH_STRICT_HOSTKEY_OFF);

    /*
     * StrictHostKeyChecking preserves the legacy low-byte normalization, while
     * PubkeyAuthentication keeps its legacy full-integer behavior so callers
     * passing -1 still land on SSH_PUBKEY_AUTH_ALL.
     */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PUBKEY_AUTH,
                         &disabled_pubkey_value);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.pubkey_auth, SSH_PUBKEY_AUTH_NO);
    assert_false((session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH) != 0);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_PUBKEY_AUTH,
                         &negative_pubkey_value);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.pubkey_auth, SSH_PUBKEY_AUTH_ALL);
    assert_true((session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH) != 0);

    rc =
        ssh_options_set(session, SSH_OPTIONS_PUBKEY_AUTH, &legacy_pubkey_value);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.pubkey_auth, SSH_PUBKEY_AUTH_ALL);
    assert_true((session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH) != 0);
}

#define EXECUTABLE_NAME "test-exec"
static void torture_options_getopt(void **state)
{
    ssh_session session = *state;
    int rc;
    int previous_level, new_level, expected_level;
    const char *argv[] = {EXECUTABLE_NAME,
                          "-l",
                          "username",
                          "-p",
                          "222",
                          "-vv",
                          "-v",
                          "-r",
                          "-c",
                          "aes128-ctr",
                          "-i",
                          "id_rsa",
                          "-C",
                          "-2",
                          "-1",
                          NULL};
    int argc = sizeof(argv)/sizeof(char *) - 1;
    previous_level = ssh_get_log_level();

    /* Test with all the supported options */
    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(argc, 1);
    assert_string_equal(argv[0], EXECUTABLE_NAME);

    /* Restore the log level to previous value first */
    new_level = ssh_get_log_level();
    expected_level = previous_level + 3; /* 2 + 1 -v's */
    if (expected_level > SSH_LOG_FUNCTIONS) {
        expected_level = SSH_LOG_FUNCTIONS;
    }
    assert_int_equal(new_level, expected_level);
    rc = ssh_set_log_level(previous_level);
    assert_int_equal(rc, SSH_OK);

    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.username, "username");
    assert_int_equal(session->opts.port, 222);
    /* The -r (usersa) is noop */
    assert_string_equal(session->opts.wanted_methods[SSH_CRYPT_C_S],
                        "aes128-ctr");
    assert_string_equal(session->opts.wanted_methods[SSH_CRYPT_S_C],
                        "aes128-ctr");
    assert_string_equal(session->opts.identity_non_exp->root->data, "id_rsa");
#ifdef WITH_ZLIB
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_C_S],
                        "zlib@openssh.com,none");
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C],
                        "zlib@openssh.com,none");
#else
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_C_S],
                        "none");
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C],
                        "none");
#endif
    /* -1 and -2 are noop */


    /* It should ignore unknown arguments */
    argv[1] = "-F";
    argv[2] = "config_file";
    argv[3] = NULL;
    argc = 3;
    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(argc, 3);
    assert_string_equal(argv[0], EXECUTABLE_NAME);
    assert_string_equal(argv[1], "-F");
    assert_string_equal(argv[2], "config_file");


    /* It should not mess with unknown arguments order */
    argv[1] = "-F";
    argv[2] = "config_file";
    argv[3] = "-M";
    argv[4] = "hmac-sha1";
    argv[5] = "-X";
    argv[6] = NULL;
    argc = 6;
    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(argc, 6);
    assert_string_equal(argv[0], EXECUTABLE_NAME);
    assert_string_equal(argv[1], "-F");
    assert_string_equal(argv[2], "config_file");
    assert_string_equal(argv[3], "-M");
    assert_string_equal(argv[4], "hmac-sha1");
    assert_string_equal(argv[5], "-X");


    /* Trailing arguments should be passed as they are */
    argv[1] = "-F";
    argv[2] = "config_file";
    argv[3] = "-M";
    argv[4] = "hmac-sha1";
    argv[5] = "example.com";
    argv[6] = NULL;
    argc = 6;
    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(argc, 6);
    assert_string_equal(argv[0], EXECUTABLE_NAME);
    assert_string_equal(argv[1], "-F");
    assert_string_equal(argv[2], "config_file");
    assert_string_equal(argv[3], "-M");
    assert_string_equal(argv[4], "hmac-sha1");
    assert_string_equal(argv[5], "example.com");

    /* Corner case: only one argument */
    argv[1] = "-C";
    argv[2] = NULL;
    argc = 2;
    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "no");
    assert_ssh_return_code(session, rc);
#ifdef WITH_ZLIB
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_C_S],
                        "none,zlib@openssh.com");
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C],
                        "none,zlib@openssh.com");
#else
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_C_S],
                        "none");
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C],
                        "none");
#endif

    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(argc, 1);
    assert_string_equal(argv[0], EXECUTABLE_NAME);
#ifdef WITH_ZLIB
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_C_S],
                        "zlib@openssh.com,none");
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C],
                        "zlib@openssh.com,none");
#else
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_C_S],
                        "none");
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C],
                        "none");
#endif

    /* Corner case: only hostname is not parsed */
    argv[1] = "example.com";
    argv[2] = NULL;
    argc = 2;
    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(argc, 2);
    assert_string_equal(argv[0], EXECUTABLE_NAME);
    assert_string_equal(argv[1], "example.com");

    /* Corner case: no arguments */
    argv[1] = NULL;
    argc = 1;
    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(argc, 1);
    assert_string_equal(argv[0], EXECUTABLE_NAME);

}

static void torture_options_getopt_o_option(void **state)
{
    ssh_session session = *state;
    int rc;
    enum ssh_config_opcode_e opcode =
        ssh_config_get_opcode((char *)"compression");
    const char *argv[6] = {EXECUTABLE_NAME, "-o", "Compression nah", NULL};
    int argc = 3;

    // Test: -o with invalid value (e.g., "-o Compression nah")
    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);

    session->opts.options_seen[opcode] = 0;

    // Test: -o with valid value (e.g., "-o Compression yes")
    argv[1] = "-o";
    argv[2] = "compression yes";
    argv[3] = NULL;
    argc = 3;

    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.options_seen[opcode], 1);

#ifdef WITH_ZLIB
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_C_S],
                        "zlib@openssh.com,none");
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C],
                        "zlib@openssh.com,none");
#else
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_C_S], "none");
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C], "none");
#endif

    // Test: -o with missing value (e.g., "-o =")
    argv[1] = "-o";
    argv[2] = "=";
    argv[3] = NULL;
    argc = 3;
    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);

    // Test: -o with only option name, no value (e.g., "-o Compression")
    session->opts.options_seen[opcode] = 0;
    argv[1] = "-o";
    argv[2] = "Compression";
    argv[3] = NULL;
    argc = 3;
    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);

    // Test: -o with empty string (e.g., "-o ")
    argv[1] = "-o";
    argv[2] = "";
    argv[3] = NULL;
    argc = 3;
    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);

    // Test: -o with unsupported option on the cli
    argv[1] = "-o";
    argv[2] = "match *";
    argv[3] = NULL;
    argc = 3;

    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);

    // Test: multiple -o options together, one invalid
    session->opts.options_seen[opcode] = 0;
    argv[1] = "-o";
    argv[2] = "compression yes";
    argv[3] = "-o";
    argv[4] = "enablesshkeysign yes";
    argv[5] = NULL;
    argc = 5;

    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);

    // Test: multiple -o options together, all valid
    session->opts.options_seen[opcode] = 0;
    argv[1] = "-o";
    argv[2] = "compression no";
    argv[3] = "-o";
    argv[4] = "rekeylimit 1G 1h";
    argv[5] = NULL;
    argc = 5;

    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);

    opcode = ssh_config_get_opcode((char *)"compression");
    assert_int_equal(session->opts.options_seen[opcode], 1);

    opcode = ssh_config_get_opcode((char *)"rekeylimit");
    assert_int_equal(session->opts.options_seen[opcode], 1);
}

static void torture_options_getopt_quiet(void **state)
{
    ssh_session session = *state;
    int rc;
    const char *argv[] = {EXECUTABLE_NAME, "-q", NULL};
    int argc = 2;

    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(argc, 1);
    assert_string_equal(argv[0], EXECUTABLE_NAME);

    assert_int_equal(ssh_get_log_level(), SSH_LOG_NOLOG);
}

static void torture_options_getopt_vq(void **state)
{
    ssh_session session = *state;
    int rc;
    const char *argv[] = {EXECUTABLE_NAME, "-v", "-q", NULL};
    int argc = 3;

    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(argc, 1);
    assert_string_equal(argv[0], EXECUTABLE_NAME);

    assert_int_equal(ssh_get_log_level(), SSH_LOG_NOLOG);
}

static void torture_options_getopt_qv(void **state)
{
    ssh_session session = *state;
    int rc;
    const char *argv[] = {EXECUTABLE_NAME, "-q", "-v", NULL};
    int argc = 3;

    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(argc, 1);
    assert_string_equal(argv[0], EXECUTABLE_NAME);

    assert_int_equal(ssh_get_log_level(), SSH_LOG_WARNING);
}

static void torture_options_getopt_nochange(void **state)
{
    ssh_session session = *state;
    int rc;
    int before = ssh_get_log_level();
    const char *argv[] = {EXECUTABLE_NAME, "host", NULL};
    int argc = 2;

    rc = ssh_options_getopt(session, &argc, (char **)argv);
    assert_ssh_return_code(session, rc);
    assert_int_equal(argc, 2);
    assert_string_equal(argv[0], EXECUTABLE_NAME);
    assert_string_equal(argv[1], "host");

    assert_int_equal(ssh_get_log_level(), before);
}

static void torture_options_plus_sign(void **state)
{
    ssh_session session = *state;
    int rc;
    const char *def_host_alg, *alg, *algs;
    char *awaited;
    size_t alg_len, algs_len;

    if (ssh_fips_mode()) {
        alg = ",rsa-sha2-512-cert-v01@openssh.com";
        algs = ",rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp521";
        def_host_alg = ssh_kex_get_fips_methods(SSH_HOSTKEYS);
    } else {
        alg = ",ssh-rsa";
        algs = ",ssh-rsa,ssh-rsa-cert-v01@openssh.com";
        def_host_alg = ssh_kex_get_default_methods(SSH_HOSTKEYS);
    }
    alg_len = strlen(alg);
    algs_len = strlen(algs);

    /* in fips mode, the default list is the available list, which means
     * we can't append anything because everything enabled is already
     * included */
    if (ssh_fips_mode()) {
        awaited = strdup(def_host_alg);
        assert_non_null(awaited);
    } else {
        awaited = calloc(strlen(def_host_alg) + alg_len + 1, 1);
        assert_non_null(awaited);

        memcpy(awaited, def_host_alg, strlen(def_host_alg));
        memcpy(awaited+strlen(def_host_alg), alg, alg_len);
    }

    if (ssh_fips_mode()) {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "+rsa-sha2-512-cert-v01@openssh.com");
    } else {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "+ssh-rsa");
    }
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        awaited);

    if (!ssh_fips_mode()) {
        /* different algorithm list is used here */
        free(awaited);

        awaited = calloc(strlen(def_host_alg) + algs_len + 1, 1);
        assert_non_null(awaited);
        memcpy(awaited, def_host_alg, strlen(def_host_alg));
        memcpy(awaited+strlen(def_host_alg), algs, algs_len);
    }

    if (ssh_fips_mode()) {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS,
                             "+rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp521");
    } else {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS,
                             "+ssh-rsa,ssh-rsa-cert-v01@openssh.com");
    }
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        awaited);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "+");
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "+blablabla");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        def_host_alg);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, NULL);
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);

    free(awaited);
}

static void torture_options_minus_sign(void **state)
{
    ssh_session session = *state;
    int rc;
    const char *def_host_alg, *alg, *algs;
    char *awaited, *p;
    size_t alg_len, algs_len;

    if (ssh_fips_mode()) {
        alg = "rsa-sha2-512-cert-v01@openssh.com,";
        algs = "rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp521,";
        def_host_alg = ssh_kex_get_fips_methods(SSH_HOSTKEYS);
    } else {
        alg = "ssh-ed25519,";
        algs = "ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,";
        def_host_alg = ssh_kex_get_default_methods(SSH_HOSTKEYS);
    }
    alg_len = strlen(alg);
    algs_len = strlen(algs);

    awaited = calloc(strlen(def_host_alg) + 1, 1);
    assert_non_null(awaited);

    memcpy(awaited, def_host_alg, strlen(def_host_alg));
    p = strstr(awaited, alg);
    assert_non_null(p);
    memmove(p, p+alg_len, strlen(p + alg_len) + 1);

    if (ssh_fips_mode()) {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "-rsa-sha2-512-cert-v01@openssh.com");
    } else {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "-ssh-ed25519");
    }
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        awaited);

    p = strstr(awaited, algs);
    assert_non_null(p);
    memmove(p, p+algs_len, strlen(p + algs_len) + 1);

    if (ssh_fips_mode()) {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "-rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp521");
    } else {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "-ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384");
    }
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        awaited);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "-");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        def_host_alg);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "-blablabla");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        def_host_alg);

    free(awaited);
}

static void torture_options_caret_sign(void **state)
{
    ssh_session session = *state;
    int rc;
    const char *def_host_alg, *alg, *algs;
    size_t alg_len, algs_len;
    char *awaited, *p;

    if (ssh_fips_mode()) {
        alg = "rsa-sha2-512-cert-v01@openssh.com,";
        algs = "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp521,";
        def_host_alg = ssh_kex_get_fips_methods(SSH_HOSTKEYS);
    } else {
        alg = "ssh-rsa,";
        algs = "ssh-rsa,ssh-rsa-cert-v01@openssh.com,";
        def_host_alg = ssh_kex_get_default_methods(SSH_HOSTKEYS);
    }
    alg_len = strlen(alg);
    algs_len = strlen(algs);

    awaited = calloc(strlen(def_host_alg) + alg_len + 1, 1);
    assert_non_null(awaited);

    memcpy(awaited, alg, alg_len);
    memcpy(awaited+alg_len, def_host_alg, strlen(def_host_alg));
    if (ssh_fips_mode()) {
        p = strstr(awaited, alg);
        /* look for second occurrence */
        p = strstr(p+1, algs);
        memmove(p, p+alg_len, strlen(p + alg_len) + 1);
    }

    if (ssh_fips_mode()) {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "^rsa-sha2-512-cert-v01@openssh.com");
    } else {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "^ssh-rsa");
    }
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        awaited);
    /* different algorithm list is used here */
    free(awaited);

    awaited = calloc(strlen(def_host_alg) + algs_len + 1, 1);
    assert_non_null(awaited);
    memcpy(awaited, algs, algs_len);
    memcpy(awaited+algs_len, def_host_alg, strlen(def_host_alg));
    if (ssh_fips_mode()) {
        p = strstr(awaited, algs);
        /* look for second occurrence */
        p = strstr(p+1, algs);
        memmove(p, p+algs_len, strlen(p + algs_len) + 1);
    }

    if (ssh_fips_mode()) {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS,
                             "^rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp521");
    } else {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS,
                             "^ssh-rsa,ssh-rsa-cert-v01@openssh.com");
    }
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        awaited);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "^");
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "^blablabla");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        def_host_alg);

    free(awaited);
}

static void torture_options_apply (void **state)
{
    ssh_session session = *state;
    struct ssh_list *awaited_list = NULL;
    struct ssh_iterator *it1 = NULL, *it2 = NULL;
    char *id = NULL;
    int rc;

    rc = ssh_options_set(session,
                         SSH_OPTIONS_KNOWNHOSTS,
                         "%%d/.ssh/known_hosts");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_GLOBAL_KNOWNHOSTS,
                         "/etc/%%u/libssh/known_hosts");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_PROXYCOMMAND,
                         "exec echo \"Hello libssh %%d!\"");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_ADD_IDENTITY,
                         "%%d/do_not_expand");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_apply(session);
    assert_ssh_return_code(session, rc);

    /* check that the values got expanded */
    assert_true(session->opts.exp_flags & SSH_OPT_EXP_FLAG_KNOWNHOSTS);
    assert_true(session->opts.exp_flags & SSH_OPT_EXP_FLAG_GLOBAL_KNOWNHOSTS);
    assert_true(session->opts.exp_flags & SSH_OPT_EXP_FLAG_PROXYCOMMAND);
    assert_true(ssh_list_count(session->opts.identity_non_exp) == 0);
    assert_true(ssh_list_count(session->opts.identity) > 0);

    /* should not change anything calling it again */
    rc = ssh_options_apply(session);
    assert_ssh_return_code(session, rc);

    /* check that the expansion was done only once */
    assert_string_equal(session->opts.knownhosts, "%d/.ssh/known_hosts");
    assert_string_equal(session->opts.global_knownhosts,
                        "/etc/%u/libssh/known_hosts");
    /* no exec should be added if there already is one */
    assert_string_equal(session->opts.ProxyCommand,
                        "exec echo \"Hello libssh %d!\"");
    assert_string_equal(session->opts.identity->root->data,
                        "%d/do_not_expand");

    /* apply should keep the freshest setting */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_KNOWNHOSTS,
                         "hello there");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_GLOBAL_KNOWNHOSTS,
                         "lorem ipsum");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_PROXYCOMMAND,
                         "mission_impossible");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_ADD_IDENTITY,
                         "007");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_ADD_IDENTITY,
                         "3");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_ADD_IDENTITY,
                         "2");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_ADD_IDENTITY,
                         "1");
    assert_ssh_return_code(session, rc);

    /* check that flags show need of escape expansion */
    assert_false(session->opts.exp_flags & SSH_OPT_EXP_FLAG_KNOWNHOSTS);
    assert_false(session->opts.exp_flags & SSH_OPT_EXP_FLAG_GLOBAL_KNOWNHOSTS);
    assert_false(session->opts.exp_flags & SSH_OPT_EXP_FLAG_PROXYCOMMAND);
    assert_false(ssh_list_count(session->opts.identity_non_exp) == 0);

    rc = ssh_options_apply(session);
    assert_ssh_return_code(session, rc);

    /* check that the values got expanded */
    assert_true(session->opts.exp_flags & SSH_OPT_EXP_FLAG_KNOWNHOSTS);
    assert_true(session->opts.exp_flags & SSH_OPT_EXP_FLAG_GLOBAL_KNOWNHOSTS);
    assert_true(session->opts.exp_flags & SSH_OPT_EXP_FLAG_PROXYCOMMAND);
    assert_true(ssh_list_count(session->opts.identity_non_exp) == 0);

    assert_string_equal(session->opts.knownhosts, "hello there");
    assert_string_equal(session->opts.global_knownhosts, "lorem ipsum");
    /* check that the "exec " was added at the beginning */
    assert_string_equal(session->opts.ProxyCommand, "exec mission_impossible");
    assert_string_equal(session->opts.identity->root->data, "1");

    /* check the order of the identity files after double expansion */
    awaited_list = ssh_list_new();
    /* append the new data in order */
    id = strdup("1");
    rc = ssh_list_append(awaited_list, id);
    assert_int_equal(rc, SSH_OK);
    id = strdup("2");
    rc = ssh_list_append(awaited_list, id);
    assert_int_equal(rc, SSH_OK);
    id = strdup("3");
    rc = ssh_list_append(awaited_list, id);
    assert_int_equal(rc, SSH_OK);
    id = strdup("007");
    rc = ssh_list_append(awaited_list, id);
    assert_int_equal(rc, SSH_OK);
    id = strdup("%d/do_not_expand");
    rc = ssh_list_append(awaited_list, id);
    assert_int_equal(rc, SSH_OK);
    /* append the defaults; this list is copied from ssh_new@src/session.c */
    id = ssh_path_expand_escape(session, "%d/.ssh/id_ed25519");
    rc = ssh_list_append(awaited_list, id);
    assert_int_equal(rc, SSH_OK);
#ifdef HAVE_ECC
    id = ssh_path_expand_escape(session, "%d/.ssh/id_ecdsa");
    rc = ssh_list_append(awaited_list, id);
    assert_int_equal(rc, SSH_OK);
#endif
    id = ssh_path_expand_escape(session, "%d/.ssh/id_rsa");
    rc = ssh_list_append(awaited_list, id);
    assert_int_equal(rc, SSH_OK);
#ifdef WITH_FIDO2
    /* Add security key identities */
    id = ssh_path_expand_escape(session, "%d/.ssh/id_ed25519_sk");
    rc = ssh_list_append(awaited_list, id);
    assert_int_equal(rc, SSH_OK);

#ifdef HAVE_ECC
    id = ssh_path_expand_escape(session, "%d/.ssh/id_ecdsa_sk");
    rc = ssh_list_append(awaited_list, id);
    assert_int_equal(rc, SSH_OK);
#endif /* HAVE_ECC */
#endif /* WITH_FIDO2 */

    assert_int_equal(ssh_list_count(awaited_list),
                     ssh_list_count(session->opts.identity));

    it1 = ssh_list_get_iterator(awaited_list);
    assert_non_null(it1);
    it2 = ssh_list_get_iterator(session->opts.identity);
    assert_non_null(it2);
    while (it1 != NULL && it2 != NULL) {
        assert_string_equal(it1->data, it2->data);

        free((void*)it1->data);
        it1 = it1->next;
        it2 = it2->next;
    }
    assert_null(it1);
    assert_null(it2);

    ssh_list_free(awaited_list);
}

static void torture_options_apply_control_path_original_host(void **state)
{
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "my-alias");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.originalhost, "my-alias");

    SAFE_FREE(session->opts.host);
    session->opts.host = strdup("192.168.1.1");
    assert_non_null(session->opts.host);

    rc = ssh_options_set(session, SSH_OPTIONS_CONTROL_PATH, "/tmp/%n-%h-%p");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_apply(session);
    assert_ssh_return_code(session, rc);
    assert_true(session->opts.exp_flags & SSH_OPT_EXP_FLAG_CONTROL_PATH);
    assert_string_equal(session->opts.control_path,
                        "/tmp/my-alias-192.168.1.1-22");
}

static void
torture_options_apply_proxycommand_original_host_config(void **state)
{
    ssh_session session = *state;
    int rc;

    torture_write_file("test_config",
                       "Host my_alias\n"
                       "\tHostName 192.168.1.1\n"
                       "\tProxyCommand echo %n-%h-%p\n");

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "my_alias");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.originalhost, "my_alias");
    assert_null(session->opts.host);

    rc = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.originalhost, "my_alias");
    assert_string_equal(session->opts.host, "192.168.1.1");
    assert_string_equal(session->opts.ProxyCommand, "echo %n-%h-%p");

    rc = ssh_options_apply(session);
    assert_ssh_return_code(session, rc);
    assert_true(session->opts.exp_flags & SSH_OPT_EXP_FLAG_PROXYCOMMAND);
    assert_string_equal(session->opts.ProxyCommand,
                        "exec echo my_alias-192.168.1.1-22");

    unlink("test_config");
}

static void torture_options_set_verbosity (void **state)
{
    ssh_session session = *state;
    int rc, new_level;

    rc = ssh_options_set(session,
                         SSH_OPTIONS_LOG_VERBOSITY_STR,
                         "3");
    assert_int_equal(rc, SSH_OK);
    new_level = ssh_get_log_level();
    assert_int_equal(new_level, SSH_LOG_PACKET);

    rc = ssh_options_set(session,
                         SSH_OPTIONS_LOG_VERBOSITY_STR,
                         "datsun");
    assert_int_equal(rc, -1);
    new_level = ssh_get_log_level();
    assert_int_not_equal(new_level, 0);
}

static void torture_options_set_batch_mode(void **state)
{
    ssh_session session = *state;
    bool val;
    int rc;

    /* Default value after setup() should be false */
    assert_false(session->opts.batch_mode);

    /* NULL value must be rejected */
    rc = ssh_options_set(session, SSH_OPTIONS_BATCH_MODE, NULL);
    assert_int_equal(rc, -1);

    /* Batch mode will be disabled */
    val = false;
    rc = ssh_options_set(session, SSH_OPTIONS_BATCH_MODE, &val);
    assert_ssh_return_code(session, rc);
    assert_false(session->opts.batch_mode);

    /* Batch mode will be enabled */
    val = true;
    rc = ssh_options_set(session, SSH_OPTIONS_BATCH_MODE, &val);
    assert_ssh_return_code(session, rc);
    assert_true(session->opts.batch_mode);
}

static void torture_options_escape_char(void **state)
{
    ssh_session session = *state;
    int val = 0;
    int result = 0;
    int rc = 0;

    /* Default value should be 0 */
    assert_int_equal(session->opts.escape_char, 0);

    /* NULL value must be rejected */
    rc = ssh_options_set(session, SSH_OPTIONS_ESCAPE_CHAR, NULL);
    assert_int_equal(rc, -1);

    /* 0 is reserved for unset and must be rejected */
    val = 0;
    rc = ssh_options_set(session, SSH_OPTIONS_ESCAPE_CHAR, &val);
    assert_int_equal(rc, -1);

    /* -1 means "none" */
    val = -1;
    rc = ssh_options_set(session, SSH_OPTIONS_ESCAPE_CHAR, &val);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_ESCAPE_CHAR, &result);
    assert_ssh_return_code(session, rc);
    assert_int_equal(result, -1);

    /* Values less than -1 must be rejected */
    val = -2;
    rc = ssh_options_set(session, SSH_OPTIONS_ESCAPE_CHAR, &val);
    assert_int_equal(rc, -1);

    /* Values greater than 255 must be rejected */
    val = 256;
    rc = ssh_options_set(session, SSH_OPTIONS_ESCAPE_CHAR, &val);
    assert_int_equal(rc, -1);

    /* Standard tilde escape */
    val = '~';
    rc = ssh_options_set(session, SSH_OPTIONS_ESCAPE_CHAR, &val);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_ESCAPE_CHAR, &result);
    assert_ssh_return_code(session, rc);
    assert_int_equal(result, '~');
}

static void torture_options_local_forward(void **state)
{
    ssh_session session = *state;
    char *value = NULL;
    int rc;

    /* Getting an unset option will fail */
    rc = ssh_options_get(session, SSH_OPTIONS_LOCAL_FORWARD, &value);
    assert_int_equal(rc, SSH_ERROR);

    /* NEXT_LOCAL_FORWARD without prior LOCAL_FORWARD will return SSH_ERROR */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_LOCAL_FORWARD, &value);
    assert_int_equal(rc, SSH_ERROR);
    assert_null(value);

    /* NULL pattern will be rejected */
    rc = ssh_options_set(session, SSH_OPTIONS_LOCAL_FORWARD, NULL);
    assert_int_equal(rc, -1);

    /* Empty pattern will be rejected */
    rc = ssh_options_set(session, SSH_OPTIONS_LOCAL_FORWARD, "");
    assert_int_equal(rc, -1);

    /* Adding two forwarding specs */
    rc = ssh_options_set(session, SSH_OPTIONS_LOCAL_FORWARD, "8080 web:80");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session, SSH_OPTIONS_LOCAL_FORWARD, "0.0.0.0:9090 db:3306");
    assert_ssh_return_code(session, rc);

    /* First entry */
    rc = ssh_options_get(session, SSH_OPTIONS_LOCAL_FORWARD, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "8080 web:80");
    ssh_string_free_char(value);
    value = NULL;

    /* Second entry */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_LOCAL_FORWARD, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "0.0.0.0:9090 db:3306");
    ssh_string_free_char(value);
    value = NULL;

    /* Iterator exhausted */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_LOCAL_FORWARD, &value);
    assert_int_equal(rc, SSH_EOF);
    assert_null(value);
}

static void torture_options_remote_forward(void **state)
{
    ssh_session session = *state;
    char *value = NULL;
    int rc;

    /* Getting an unset option will fail */
    rc = ssh_options_get(session, SSH_OPTIONS_REMOTE_FORWARD, &value);
    assert_int_equal(rc, SSH_ERROR);

    /* NEXT_REMOTE_FORWARD without prior REMOTE_FORWARD will return SSH_ERROR */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_REMOTE_FORWARD, &value);
    assert_int_equal(rc, SSH_ERROR);
    assert_null(value);

    /* NULL pattern will be rejected */
    rc = ssh_options_set(session, SSH_OPTIONS_REMOTE_FORWARD, NULL);
    assert_int_equal(rc, -1);

    /* Empty pattern will be rejected */
    rc = ssh_options_set(session, SSH_OPTIONS_REMOTE_FORWARD, "");
    assert_int_equal(rc, -1);

    /* Adding two forwarding specs */
    rc = ssh_options_set(session, SSH_OPTIONS_REMOTE_FORWARD, "8080 web:80");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session, SSH_OPTIONS_REMOTE_FORWARD, "0.0.0.0:9090 db:3306");
    assert_ssh_return_code(session, rc);

    /* First entry */
    rc = ssh_options_get(session, SSH_OPTIONS_REMOTE_FORWARD, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "8080 web:80");
    ssh_string_free_char(value);
    value = NULL;

    /* Second entry */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_REMOTE_FORWARD, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "0.0.0.0:9090 db:3306");
    ssh_string_free_char(value);
    value = NULL;

    /* Iterator exhausted */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_REMOTE_FORWARD, &value);
    assert_int_equal(rc, SSH_EOF);
    assert_null(value);
}

static void torture_options_set_preferred_authentications(void **state)
{
    ssh_session session = *state;
    char *value = NULL;
    int rc;

    /* Default value after setup() should be NULL */
    assert_null(session->opts.preferred_authentications);

    /* Getting an unset option will fail */
    rc = ssh_options_get(session,
                         SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                         &value);
    assert_int_not_equal(rc, SSH_OK);
    assert_null(value);

    /* NULL value should clear the option */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                         NULL);
    assert_ssh_return_code(session, rc);
    assert_null(session->opts.preferred_authentications);

    /* Valid comma-separated list */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                         "publickey,password");
    assert_ssh_return_code(session, rc);
    assert_string_equal(session->opts.preferred_authentications,
                        "publickey,password");

    /* Getting a set option should succeed and return the same value */
    rc = ssh_options_get(session,
                         SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                         &value);
    assert_ssh_return_code(session, rc);
    assert_string_equal(value, "publickey,password");
    ssh_string_free_char(value);
    value = NULL;

    /* Empty string is an error and it would silently block all auth */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                         "");
    assert_int_equal(rc, -1);

    /* Set a different value and verify get round-trip */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                         "publickey");
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get(session,
                         SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                         &value);
    assert_ssh_return_code(session, rc);
    assert_string_equal(value, "publickey");
    ssh_string_free_char(value);
    value = NULL;

    /* Clear the option with NULL */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                         NULL);
    assert_ssh_return_code(session, rc);
    assert_null(session->opts.preferred_authentications);

    /* Getting a cleared option should fail */
    rc = ssh_options_get(session,
                         SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                         &value);
    assert_int_not_equal(rc, SSH_OK);
    assert_null(value);
}

static void torture_options_userauth_list_no_preference(void **state)
{
    ssh_session session = *state;
    int methods = 0;

    /* Set up a known set of server-advertised methods */
    session->auth.supported_methods = SSH_AUTH_METHOD_PUBLICKEY |
                                      SSH_AUTH_METHOD_PASSWORD |
                                      SSH_AUTH_METHOD_INTERACTIVE;

    /* Without PreferredAuthentications, ssh_userauth_list returns all */
    methods = ssh_userauth_list(session, NULL);
    assert_int_equal(methods, SSH_AUTH_METHOD_PUBLICKEY |
                              SSH_AUTH_METHOD_PASSWORD |
                              SSH_AUTH_METHOD_INTERACTIVE);
}

static void torture_options_userauth_list_filter_subset(void **state)
{
    ssh_session session = *state;
    int methods = 0;

    session->auth.supported_methods = SSH_AUTH_METHOD_PUBLICKEY |
                                      SSH_AUTH_METHOD_PASSWORD |
                                      SSH_AUTH_METHOD_INTERACTIVE |
                                      SSH_AUTH_METHOD_HOSTBASED;

    /* Whitespace around method names should be trimmed by ssh_userauth_list */
    ssh_options_set(session,
                    SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                    " publickey ,  password ");
    methods = ssh_userauth_list(session, NULL);
    assert_int_equal(methods, SSH_AUTH_METHOD_PUBLICKEY |
                              SSH_AUTH_METHOD_PASSWORD);
}

static void torture_options_userauth_list_method_not_supported(void **state)
{
    ssh_session session = *state;
    int methods = 0;

    session->auth.supported_methods = SSH_AUTH_METHOD_GSSAPI_MIC;

    ssh_options_set(session,
                    SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                    "publickey,password");
    methods = ssh_userauth_list(session, NULL);
    assert_int_equal(methods, 0);
}

static void torture_options_userauth_list_unknown_method_ignored(void **state)
{
    ssh_session session = *state;
    int methods = 0;

    session->auth.supported_methods = SSH_AUTH_METHOD_PUBLICKEY |
                                      SSH_AUTH_METHOD_PASSWORD;

    ssh_options_set(session,
                    SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                    "publickey,garbage,password");
    methods = ssh_userauth_list(session, NULL);
    assert_int_equal(methods, SSH_AUTH_METHOD_PUBLICKEY |
                              SSH_AUTH_METHOD_PASSWORD);
}

static void torture_options_number_of_password_prompts(void **state)
{
    ssh_session session = *state;
    int val = 0;
    int result = 0;
    int rc = 0;

    /* Default should be 0 */
    assert_int_equal(session->opts.number_of_password_prompts, 0);

    /* NULL will be rejected */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS,
                         NULL);
    assert_int_equal(rc, -1);

    /* 0 is not a valid prompt count */
    val = 0;
    rc = ssh_options_set(session,
                         SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS,
                         &val);
    assert_int_equal(rc, -1);

    /* Negative is not a valid prompt count */
    val = -1;
    rc = ssh_options_set(session,
                         SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS,
                         &val);
    assert_int_equal(rc, -1);

    /* 3 is the OpenSSH default which will be accepted */
    val = 3;
    rc = ssh_options_set(session,
                         SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS,
                         &val);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.number_of_password_prompts, 3);

    /* Verify get returns the same value we just set */
    rc = ssh_options_get_int(session,
                             SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS,
                             &result);
    assert_ssh_return_code(session, rc);
    assert_int_equal(result, 3);

    /* 1 is the minimum sensible value */
    val = 1;
    rc = ssh_options_set(session,
                         SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS,
                         &val);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.number_of_password_prompts, 1);
}

static void torture_options_set_request_tty(void **state)
{
    ssh_session session = *state;
    int val = 0;
    int rc = 0;

    /* Default value should be SSH_REQUEST_TTY_NO */
    assert_int_equal(session->opts.request_tty, SSH_REQUEST_TTY_NO);

    /* NULL value must be rejected */
    rc = ssh_options_set(session, SSH_OPTIONS_REQUEST_TTY, NULL);
    assert_int_equal(rc, -1);

    /* Valid values */
    val = SSH_REQUEST_TTY_NO;
    rc = ssh_options_set(session, SSH_OPTIONS_REQUEST_TTY, &val);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.request_tty, SSH_REQUEST_TTY_NO);

    val = SSH_REQUEST_TTY_YES;
    rc = ssh_options_set(session, SSH_OPTIONS_REQUEST_TTY, &val);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.request_tty, SSH_REQUEST_TTY_YES);

    val = SSH_REQUEST_TTY_AUTO;
    rc = ssh_options_set(session, SSH_OPTIONS_REQUEST_TTY, &val);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.request_tty, SSH_REQUEST_TTY_AUTO);

    val = SSH_REQUEST_TTY_FORCE;
    rc = ssh_options_set(session, SSH_OPTIONS_REQUEST_TTY, &val);
    assert_ssh_return_code(session, rc);
    assert_int_equal(session->opts.request_tty, SSH_REQUEST_TTY_FORCE);

    /* Invalid value must be rejected */
    val = -1;
    rc = ssh_options_set(session, SSH_OPTIONS_REQUEST_TTY, &val);
    assert_int_equal(rc, -1);

    val = 100;
    rc = ssh_options_set(session, SSH_OPTIONS_REQUEST_TTY, &val);
    assert_int_equal(rc, -1);
}

static void torture_options_send_env(void **state)
{
    ssh_session session = *state;
    char *value = NULL;
    int rc;

    /* Getting an unset option will fail */
    rc = ssh_options_get(session, SSH_OPTIONS_SEND_ENV, &value);
    assert_int_not_equal(rc, SSH_OK);

    /* NEXT_SEND_ENV without prior SEND_ENV must return SSH_ERROR */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_SEND_ENV, &value);
    assert_int_equal(rc, SSH_ERROR);
    assert_null(value);

    /* NULL pattern must be rejected */
    rc = ssh_options_set(session, SSH_OPTIONS_SEND_ENV, NULL);
    assert_int_equal(rc, -1);

    /* Empty pattern must be rejected */
    rc = ssh_options_set(session, SSH_OPTIONS_SEND_ENV, "");
    assert_int_equal(rc, -1);

    /* Adding two patterns */
    rc = ssh_options_set(session, SSH_OPTIONS_SEND_ENV, "LANG");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session, SSH_OPTIONS_SEND_ENV, "LC_*");
    assert_ssh_return_code(session, rc);

    /* First pattern */
    rc = ssh_options_get(session, SSH_OPTIONS_SEND_ENV, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "LANG");
    ssh_string_free_char(value);
    value = NULL;

    /* Second pattern */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_SEND_ENV, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "LC_*");
    ssh_string_free_char(value);
    value = NULL;

    /* Iterator exhausted */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_SEND_ENV, &value);
    assert_int_equal(rc, SSH_EOF);
    assert_null(value);

    /* '-' alone (empty pattern after prefix) must be rejected */
    rc = ssh_options_set(session, SSH_OPTIONS_SEND_ENV, "-");
    assert_int_equal(rc, -1);

    /* Removing an existing pattern */
    rc = ssh_options_set(session, SSH_OPTIONS_SEND_ENV, "LANG");
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session, SSH_OPTIONS_SEND_ENV, "-LANG");
    assert_ssh_return_code(session, rc);

    /* Only LC_* should remain */
    rc = ssh_options_get(session, SSH_OPTIONS_SEND_ENV, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "LC_*");
    ssh_string_free_char(value);
    value = NULL;

    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_SEND_ENV, &value);
    assert_int_equal(rc, SSH_EOF);
    assert_null(value);

    /* Removing a non-existing pattern should not affect existing patterns */
    rc = ssh_options_set(session, SSH_OPTIONS_SEND_ENV, "-NONEXIST");
    assert_ssh_return_code(session, rc);

    /* LC_* should still be there */
    rc = ssh_options_get(session, SSH_OPTIONS_SEND_ENV, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "LC_*");
    ssh_string_free_char(value);
    value = NULL;

    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_SEND_ENV, &value);
    assert_int_equal(rc, SSH_EOF);
    assert_null(value);
}

static void torture_options_get_int(void **state)
{
    ssh_session session = *state;
    bool bval;
    int ival;
    int result;
    int rc;

    /* NULL session must be rejected */
    rc = ssh_options_get_int(NULL, SSH_OPTIONS_BATCH_MODE, &result);
    assert_int_equal(rc, SSH_ERROR);

    /* NULL output pointer must be rejected */
    rc = ssh_options_get_int(session, SSH_OPTIONS_BATCH_MODE, NULL);
    assert_int_equal(rc, SSH_ERROR);

    /* Unsupported option type must be rejected */
    rc = ssh_options_get_int(session, SSH_OPTIONS_HOST, &result);
    assert_int_equal(rc, SSH_ERROR);

    /* SSH_OPTIONS_ADDRESS_FAMILY default should be ANY */
    rc = ssh_options_get_int(session, SSH_OPTIONS_ADDRESS_FAMILY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_ADDRESS_FAMILY_ANY);

    /* After setting to INET, getter should return INET */
    ival = SSH_ADDRESS_FAMILY_INET;
    rc = ssh_options_set(session, SSH_OPTIONS_ADDRESS_FAMILY, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_ADDRESS_FAMILY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_ADDRESS_FAMILY_INET);

    /* After setting back to ANY, getter should return ANY */
    ival = SSH_ADDRESS_FAMILY_ANY;
    rc = ssh_options_set(session, SSH_OPTIONS_ADDRESS_FAMILY, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_ADDRESS_FAMILY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_ADDRESS_FAMILY_ANY);

    /* SSH_OPTIONS_CONTROL_MASTER: default should be SSH_CONTROL_MASTER_NO */
    rc = ssh_options_get_int(session, SSH_OPTIONS_CONTROL_MASTER, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_CONTROL_MASTER_NO);

    /* After setting to AUTO, getter should return AUTO */
    ival = SSH_CONTROL_MASTER_AUTO;
    rc = ssh_options_set(session, SSH_OPTIONS_CONTROL_MASTER, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_CONTROL_MASTER, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_CONTROL_MASTER_AUTO);

    /* SSH_OPTIONS_IDENTITIES_ONLY : default should be 0 */
    rc = ssh_options_get_int(session, SSH_OPTIONS_IDENTITIES_ONLY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 0);

    /* After enabling, getter should return 1 */
    bval = true;
    rc = ssh_options_set(session, SSH_OPTIONS_IDENTITIES_ONLY, &bval);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_IDENTITIES_ONLY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 1);

    /* SSH_OPTIONS_LOG_VERBOSITY: default should be SSH_LOG_NOLOG */
    rc = ssh_options_get_int(session, SSH_OPTIONS_LOG_VERBOSITY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_LOG_NOLOG);

    /* After setting to WARNING, getter should return WARNING */
    ival = SSH_LOG_WARNING;
    rc = ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_LOG_VERBOSITY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_LOG_WARNING);

    /* SSH_OPTIONS_STRICTHOSTKEYCHECK: default should be ASK */
    rc = ssh_options_get_int(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_STRICT_HOSTKEY_ASK);

    /* After disabling, getter should return OFF */
    ival = 0;
    rc = ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_STRICT_HOSTKEY_OFF);

    /* SSH_OPTIONS_NODELAY: default should be 0 */
    rc = ssh_options_get_int(session, SSH_OPTIONS_NODELAY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 0);

    /* After enabling, getter should return 1 */
    ival = 1;
    rc = ssh_options_set(session, SSH_OPTIONS_NODELAY, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_NODELAY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 1);

    /* SSH_OPTIONS_RSA_MIN_SIZE: default should be 0 */
    rc = ssh_options_get_int(session, SSH_OPTIONS_RSA_MIN_SIZE, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 0);

    /* After setting to RSA_MIN_KEY_SIZE, getter will return RSA_MIN_KEY_SIZE */
    ival = RSA_MIN_KEY_SIZE;
    rc = ssh_options_set(session, SSH_OPTIONS_RSA_MIN_SIZE, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_RSA_MIN_SIZE, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, RSA_MIN_KEY_SIZE);

    /* SSH_OPTIONS_PASSWORD_AUTH : enabled by default */
    rc = ssh_options_get_int(session, SSH_OPTIONS_PASSWORD_AUTH, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 1);

    /* After disabling password auth, getter should return 0 */
    ival = 0;
    rc = ssh_options_set(session, SSH_OPTIONS_PASSWORD_AUTH, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_PASSWORD_AUTH, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 0);

    /* After re-enabling password auth, getter should return 1 */
    ival = 1;
    rc = ssh_options_set(session, SSH_OPTIONS_PASSWORD_AUTH, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_PASSWORD_AUTH, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 1);

    /* SSH_OPTIONS_PUBKEY_AUTH (bitmask field): enabled by default */
    rc = ssh_options_get_int(session, SSH_OPTIONS_PUBKEY_AUTH, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 1);

    /* After disabling pubkey auth, getter should return 0 */
    ival = 0;
    rc = ssh_options_set(session, SSH_OPTIONS_PUBKEY_AUTH, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_PUBKEY_AUTH, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 0);

    /* SSH_OPTIONS_KBDINT_AUTH : enabled by default */
    rc = ssh_options_get_int(session, SSH_OPTIONS_KBDINT_AUTH, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 1);

    /* After disabling kbdint auth, getter should return 0 */
    ival = 0;
    rc = ssh_options_set(session, SSH_OPTIONS_KBDINT_AUTH, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_KBDINT_AUTH, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 0);

    /* SSH_OPTIONS_GSSAPI_AUTH : enabled by default */
    rc = ssh_options_get_int(session, SSH_OPTIONS_GSSAPI_AUTH, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 1);

    /* After disabling gssapi auth, getter should return 0 */
    ival = 0;
    rc = ssh_options_set(session, SSH_OPTIONS_GSSAPI_AUTH, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_GSSAPI_AUTH, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 0);

    /* SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS: default should be 0 */
    rc = ssh_options_get_int(session, SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
                             &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 0);

    /* After enabling, getter should return 1 */
    ival = 1;
    rc = ssh_options_set(session, SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
                         &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
                             &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 1);

    /* SSH_OPTIONS_BATCH_MODE default should be 0 */
    rc = ssh_options_get_int(session, SSH_OPTIONS_BATCH_MODE, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 0);

    /* After enabling batch mode, getter should return 1 */
    bval = true;
    rc = ssh_options_set(session, SSH_OPTIONS_BATCH_MODE, &bval);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_BATCH_MODE, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 1);

    /* After disabling batch mode, getter should return 0 */
    bval = false;
    rc = ssh_options_set(session, SSH_OPTIONS_BATCH_MODE, &bval);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_BATCH_MODE, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 0);

    /* SSH_OPTIONS_PORT: default should return 22 */
    rc = ssh_options_get_int(session, SSH_OPTIONS_PORT, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 22);

    /* After setting port to 2222, getter should return 2222 */
    ival = 2222;
    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_PORT, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 2222);

    /* SSH_OPTIONS_REQUEST_TTY default should be SSH_REQUEST_TTY_NO */
    rc = ssh_options_get_int(session, SSH_OPTIONS_REQUEST_TTY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_REQUEST_TTY_NO);

    /* After setting to YES, getter should return YES */
    ival = SSH_REQUEST_TTY_YES;
    rc = ssh_options_set(session, SSH_OPTIONS_REQUEST_TTY, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_REQUEST_TTY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_REQUEST_TTY_YES);

    /* After setting to AUTO, getter should return AUTO */
    ival = SSH_REQUEST_TTY_AUTO;
    rc = ssh_options_set(session, SSH_OPTIONS_REQUEST_TTY, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_REQUEST_TTY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_REQUEST_TTY_AUTO);

    /* After setting to FORCE, getter should return FORCE */
    ival = SSH_REQUEST_TTY_FORCE;
    rc = ssh_options_set(session, SSH_OPTIONS_REQUEST_TTY, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_REQUEST_TTY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_REQUEST_TTY_FORCE);

    /* After setting back to NO, getter should return NO */
    ival = SSH_REQUEST_TTY_NO;
    rc = ssh_options_set(session, SSH_OPTIONS_REQUEST_TTY, &ival);
    assert_ssh_return_code(session, rc);
    rc = ssh_options_get_int(session, SSH_OPTIONS_REQUEST_TTY, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, SSH_REQUEST_TTY_NO);
}

static void torture_options_set_rsa_min_size(void **state)
{
    ssh_session session = *state;
    int min_allowed = RSA_MIN_KEY_SIZE, key_size, rc;

    /* Check that passing NULL leads to failure */
    rc = ssh_options_set(session, SSH_OPTIONS_RSA_MIN_SIZE, NULL);
    assert_int_equal(rc, -1);

    /*
     * Check that supplying a value less than the allowed minimum leads
     * to failure
     */
    key_size = min_allowed - 2;
    rc = ssh_options_set(session, SSH_OPTIONS_RSA_MIN_SIZE, &key_size);
    assert_int_equal(rc, -1);

    /* Check that supplying a negative value leads to failure */
    key_size = -10;
    rc = ssh_options_set(session, SSH_OPTIONS_RSA_MIN_SIZE, &key_size);
    assert_int_equal(rc, -1);

    /* Check that supplying 0 succeeds (used to revert to default) */
    key_size = 0;
    rc = ssh_options_set(session, SSH_OPTIONS_RSA_MIN_SIZE, &key_size);
    assert_ssh_return_code(session, rc);

    /* Check that supplying allowed minimum succeeds */
    key_size = min_allowed;
    rc = ssh_options_set(session, SSH_OPTIONS_RSA_MIN_SIZE, &key_size);
    assert_ssh_return_code(session, rc);

    /* Check that supplying a value greater than allowed minimum succeeds */
    key_size = min_allowed + 10;
    rc = ssh_options_set(session, SSH_OPTIONS_RSA_MIN_SIZE, &key_size);
    assert_ssh_return_code(session, rc);
}

static void torture_options_set_auth_flags(void **state)
{
    ssh_session session = *state;
    int on = 1;
    int off = 0;
    int rc;

    /* All auth flags should be on by default */
    assert_true(session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH);
    assert_true(session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH);
    assert_true(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);
    assert_true(session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH);

    /* NULL value should fail */
    rc = ssh_options_set(session, SSH_OPTIONS_PASSWORD_AUTH, NULL);
    assert_int_equal(rc, -1);

    /* Disable each flag and verify it is cleared */
    rc = ssh_options_set(session, SSH_OPTIONS_PASSWORD_AUTH, &off);
    assert_int_equal(rc, SSH_OK);
    assert_false(session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH);

    rc = ssh_options_set(session, SSH_OPTIONS_PUBKEY_AUTH, &off);
    assert_int_equal(rc, SSH_OK);
    assert_false(session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH);

    rc = ssh_options_set(session, SSH_OPTIONS_KBDINT_AUTH, &off);
    assert_int_equal(rc, SSH_OK);
    assert_false(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    rc = ssh_options_set(session, SSH_OPTIONS_GSSAPI_AUTH, &off);
    assert_int_equal(rc, SSH_OK);
    assert_false(session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH);

    /* Re-enable each flag and verify it is set */
    rc = ssh_options_set(session, SSH_OPTIONS_PASSWORD_AUTH, &on);
    assert_int_equal(rc, SSH_OK);
    assert_true(session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH);

    rc = ssh_options_set(session, SSH_OPTIONS_PUBKEY_AUTH, &on);
    assert_int_equal(rc, SSH_OK);
    assert_true(session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH);

    rc = ssh_options_set(session, SSH_OPTIONS_KBDINT_AUTH, &on);
    assert_int_equal(rc, SSH_OK);
    assert_true(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    rc = ssh_options_set(session, SSH_OPTIONS_GSSAPI_AUTH, &on);
    assert_int_equal(rc, SSH_OK);
    assert_true(session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH);
}

#ifdef WITH_SERVER
const char template[] = "temp_dir_XXXXXX";

struct bind_st {
    char *cwd;
    char *temp_dir;
    ssh_bind bind;
};

static int ssh_bind_setup_files(void **state)
{
    struct bind_st *test_state = NULL;
    char *cwd = NULL;
    char *tmp_dir = NULL;
    int rc = 0;

    test_state = (struct bind_st *)malloc(sizeof(struct bind_st));
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

    /* For ed25519 the test keys are not available in legacy PEM format. Using
     * the new OpenSSH format for all algorithms */
    torture_write_file(LIBSSH_RSA_TESTKEY,
                       torture_get_openssh_testkey(SSH_KEYTYPE_RSA, 0));

    torture_write_file(LIBSSH_ED25519_TESTKEY,
                       torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 0));
#ifdef HAVE_ECC
    torture_write_file(LIBSSH_ECDSA_521_TESTKEY,
                       torture_get_openssh_testkey(SSH_KEYTYPE_ECDSA_P521, 0));
#endif
    torture_write_file(LIBSSH_CUSTOM_BIND_CONFIG_FILE,
                       "Port 42\n");
    return 0;
}


/* sshbind options */
static int sshbind_setup(void **state)
{
    int rc;
    struct bind_st *test_state = NULL;

    rc = ssh_bind_setup_files((void **)&test_state);
    assert_int_equal(rc, 0);
    assert_non_null(test_state);

    test_state->bind = ssh_bind_new();
    assert_non_null(test_state->bind);

    *state = test_state;

    return 0;
}

static int sshbind_teardown(void **state)
{
    struct bind_st *test_state = NULL;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);

    assert_non_null(test_state);
    assert_non_null(test_state->cwd);
    assert_non_null(test_state->temp_dir);
    assert_non_null(test_state->bind);

    rc = torture_change_dir(test_state->cwd);
    assert_int_equal(rc, 0);

    rc = torture_rmdirs(test_state->temp_dir);
    assert_int_equal(rc, 0);

    SAFE_FREE(test_state->temp_dir);
    SAFE_FREE(test_state->cwd);
    ssh_bind_free(test_state->bind);
    SAFE_FREE(test_state);

    return 0;
}

static void
torture_bind_options_import_key(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;
    const char *base64_key;
    ssh_key key = ssh_key_new();

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    /* set null */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, NULL);
    assert_int_equal(rc, -1);
    /* set invalid key */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, key);
    assert_int_equal(rc, -1);
    SSH_KEY_FREE(key);

    /* set ed25519 key */
    base64_key = torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 0);
    rc = ssh_pki_import_privkey_base64(base64_key, NULL, NULL, NULL, &key);
    if (ssh_fips_mode()) {
        assert_int_equal(rc, SSH_ERROR);
        assert_null(key);
    } else {
        assert_int_equal(rc, SSH_OK);
        assert_non_null(key);
    }

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, key);
    if (ssh_fips_mode()) {
        assert_int_equal(rc, SSH_ERROR);
    } else {
        assert_int_equal(rc, 0);
    }

    /* set rsa key */
    base64_key = torture_get_testkey(SSH_KEYTYPE_RSA, 0);
    rc = ssh_pki_import_privkey_base64(base64_key, NULL, NULL, NULL, &key);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(key);

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, key);
    assert_int_equal(rc, 0);
#ifdef HAVE_ECC
    /* set ecdsa key */
    base64_key = torture_get_testkey(SSH_KEYTYPE_ECDSA_P521, 0);
    rc = ssh_pki_import_privkey_base64(base64_key, NULL, NULL, NULL, &key);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(key);

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, key);
    assert_int_equal(rc, 0);
#endif
}

static void
torture_bind_options_import_key_str(void **state)
{
    struct bind_st *test_state = NULL;
    ssh_bind bind = NULL;
    int rc;
    const char *base64_key = "";

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    /* set null */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY_STR, NULL);
    assert_int_equal(rc, -1);
    /* set invalid key */
    rc =
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY_STR, base64_key);
    assert_int_equal(rc, -1);

    /* set ed25519 key */
    base64_key = torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 0);

    rc =
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY_STR, base64_key);
    if (ssh_fips_mode()) {
        assert_int_equal(rc, SSH_ERROR);
    } else {
        assert_int_equal(rc, 0);
    }

    /* set rsa key */
    base64_key = torture_get_testkey(SSH_KEYTYPE_RSA, 0);

    rc =
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY_STR, base64_key);
    assert_int_equal(rc, 0);
#ifdef HAVE_ECC
    /* set ecdsa key */
    base64_key = torture_get_testkey(SSH_KEYTYPE_ECDSA_P521, 0);

    rc =
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY_STR, base64_key);
    assert_int_equal(rc, 0);
#endif
}

static void torture_bind_options_hostkey(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    /* Test RSA key */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HOSTKEY,
                              LIBSSH_RSA_TESTKEY);
    assert_int_equal(rc, 0);
    assert_non_null(bind->rsakey);
    assert_string_equal(bind->rsakey, LIBSSH_RSA_TESTKEY);

    /* Test ED25519 key */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HOSTKEY,
                              LIBSSH_ED25519_TESTKEY);
    if (ssh_fips_mode()) {
        assert_int_equal(rc, SSH_ERROR);
        assert_null(bind->ed25519key);
    } else {
        assert_int_equal(rc, 0);
        assert_non_null(bind->ed25519key);
        assert_string_equal(bind->ed25519key, LIBSSH_ED25519_TESTKEY);
    }

#ifdef HAVE_ECC
    /* Test ECDSA key */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HOSTKEY,
                              LIBSSH_ECDSA_521_TESTKEY);
    assert_int_equal(rc, 0);
    assert_non_null(bind->ecdsakey);
    assert_string_equal(bind->ecdsakey, LIBSSH_ECDSA_521_TESTKEY);
#endif
}

static void torture_bind_options_bindaddr(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;

    const char *address = "127.0.0.1";

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDADDR, address);
    assert_int_equal(rc, 0);
    assert_non_null(bind->bindaddr);
    assert_string_equal(bind->bindaddr, address);
}

static void torture_bind_options_bindport(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    unsigned int given_port = 1234;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT, &given_port);
    assert_int_equal(rc, 0);
    assert_int_equal(bind->bindport, 1234);
}

static void torture_bind_options_bindport_str(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT_STR, "23");
    assert_int_equal(rc, 0);
    assert_int_equal(bind->bindport, 23);

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT_STR, "twentythree");
    assert_int_equal(rc, -1);
    assert_int_not_equal(bind->bindport, 0);
}

static void torture_bind_options_log_verbosity(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int verbosity = SSH_LOG_PACKET;
    int previous_level, new_level;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    previous_level = ssh_get_log_level();

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);
    assert_int_equal(rc, 0);

    new_level = ssh_get_log_level();
    assert_int_equal(new_level, verbosity);

    rc = ssh_set_log_level(previous_level);
    assert_int_equal(rc, SSH_OK);
}

static void torture_bind_options_log_verbosity_str(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;
    int previous_level, new_level;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    previous_level = ssh_get_log_level();

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");
    assert_int_equal(rc, 0);

    new_level = ssh_get_log_level();
    assert_int_equal(new_level, SSH_LOG_PACKET);

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "verbosity");
    assert_int_equal(rc, -1);
    new_level = ssh_get_log_level();
    assert_int_not_equal(new_level, 0);

    rc = ssh_set_log_level(previous_level);
    assert_int_equal(rc, SSH_OK);
}

static void torture_bind_options_rsakey(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HOSTKEY,
                              LIBSSH_RSA_TESTKEY);
    assert_int_equal(rc, 0);
    assert_non_null(bind->rsakey);
    assert_string_equal(bind->rsakey, LIBSSH_RSA_TESTKEY);
}

static void torture_bind_options_set_rsa_min_size(void **state)
{
    struct bind_st *test_state = NULL;
    ssh_bind bind = NULL;
    int rc, min_allowed = RSA_MIN_KEY_SIZE, key_size;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    /* Check that passing NULL leads to failure */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSA_MIN_SIZE, NULL);
    assert_int_equal(rc, -1);

    /*
     * Check that supplying a value less than the allowed minimum leads
     * to failure
     */
    key_size = min_allowed - 2;
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSA_MIN_SIZE, &key_size);
    assert_int_equal(rc, -1);

    /* Check that supplying a negative value leads to failure */
    key_size = -10;
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSA_MIN_SIZE, &key_size);
    assert_int_equal(rc, -1);

    /* Check that supplying 0 succeeds (used to revert to default) */
    key_size = 0;
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSA_MIN_SIZE, &key_size);
    assert_int_equal(rc, 0);

    /* Check that supplying allowed minimum succeeds */
    key_size = min_allowed;
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSA_MIN_SIZE, &key_size);
    assert_int_equal(rc, 0);

    /* Check that supplying a value greater than allowed minimum succeeds */
    key_size = min_allowed + 10;
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSA_MIN_SIZE, &key_size);
    assert_int_equal(rc, 0);
}

#ifdef HAVE_ECC
static void torture_bind_options_ecdsakey(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HOSTKEY,
                              LIBSSH_ECDSA_521_TESTKEY);
    assert_int_equal(rc, 0);
    assert_non_null(bind->ecdsakey);
    assert_string_equal(bind->ecdsakey, LIBSSH_ECDSA_521_TESTKEY);
}
#endif

static void torture_bind_options_banner(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    const char *banner = "This is the new banner";
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_BANNER,
                              banner);
    assert_int_equal(rc, 0);
    assert_non_null(bind->banner);
    assert_string_equal(bind->banner, banner);
}

static void torture_bind_options_set_ciphers(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;
    assert_non_null(bind->wanted_methods);

    /* Test known ciphers */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_CIPHERS_C_S,
                              "aes128-ctr,aes192-ctr,aes256-ctr");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_CRYPT_C_S]);
    if (ssh_fips_mode()) {
        assert_string_equal(bind->wanted_methods[SSH_CRYPT_C_S],
                            "aes128-ctr,aes256-ctr");
    } else {
        assert_string_equal(bind->wanted_methods[SSH_CRYPT_C_S],
                            "aes128-ctr,aes192-ctr,aes256-ctr");
    }

    /* Test one unknown cipher */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_CIPHERS_C_S,
                         "aes128-ctr,unknown-crap@example.com,aes256-ctr");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_CRYPT_C_S]);
    assert_string_equal(bind->wanted_methods[SSH_CRYPT_C_S],
                        "aes128-ctr,aes256-ctr");

    /* Test all unknown ciphers */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_CIPHERS_C_S,
                         "unknown-crap@example.com,more-crap@example.com");
    assert_int_not_equal(rc, 0);

    /* Test known ciphers */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_CIPHERS_S_C,
                              "aes128-ctr,aes192-ctr,aes256-ctr");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_CRYPT_S_C]);
    if (ssh_fips_mode()) {
        assert_string_equal(bind->wanted_methods[SSH_CRYPT_S_C],
                            "aes128-ctr,aes256-ctr");
    } else {
        assert_string_equal(bind->wanted_methods[SSH_CRYPT_S_C],
                            "aes128-ctr,aes192-ctr,aes256-ctr");
    }

    /* Test one unknown cipher */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_CIPHERS_S_C,
                         "aes128-ctr,unknown-crap@example.com,aes256-ctr");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_CRYPT_S_C]);
    assert_string_equal(bind->wanted_methods[SSH_CRYPT_S_C],
                        "aes128-ctr,aes256-ctr");

    /* Test all unknown ciphers */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_CIPHERS_S_C,
                         "unknown-crap@example.com,more-crap@example.com");
    assert_int_not_equal(rc, 0);
}

static void torture_bind_options_set_key_exchange(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;
    assert_non_null(bind->wanted_methods);

    /* Test known kexes */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_KEY_EXCHANGE,
                              "curve25519-sha256,curve25519-sha256@libssh.org,"
                              "ecdh-sha2-nistp256,diffie-hellman-group16-sha512,"
                              "diffie-hellman-group18-sha512,"
                              "diffie-hellman-group14-sha256,"
                              "diffie-hellman-group14-sha1");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_KEX]);
    if (ssh_fips_mode()) {
        assert_string_equal(bind->wanted_methods[SSH_KEX],
                            "ecdh-sha2-nistp256,diffie-hellman-group16-sha512,"
                            "diffie-hellman-group18-sha512,"
                            "diffie-hellman-group14-sha256");
    } else {
        assert_string_equal(bind->wanted_methods[SSH_KEX],
                            "curve25519-sha256,curve25519-sha256@libssh.org,"
                            "ecdh-sha2-nistp256,diffie-hellman-group16-sha512,"
                            "diffie-hellman-group18-sha512,"
                            "diffie-hellman-group14-sha256,"
                            "diffie-hellman-group14-sha1");
    }

    /* Test one unknown kex */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_KEY_EXCHANGE,
                         "diffie-hellman-group16-sha512,"
                         "unknown-crap@example.com,"
                         "diffie-hellman-group18-sha512");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_KEX]);
    assert_string_equal(bind->wanted_methods[SSH_KEX],
                        "diffie-hellman-group16-sha512,"
                        "diffie-hellman-group18-sha512");

    /* Test all unknown kexes */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_KEY_EXCHANGE,
                              "unknown-crap@example.com,more-crap@example.com");
    assert_int_not_equal(rc, 0);
}

static void torture_bind_options_set_macs(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;
    assert_non_null(bind->wanted_methods);

    /* Test known MACs */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HMAC_S_C, "hmac-sha1");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_MAC_S_C]);
    assert_string_equal(bind->wanted_methods[SSH_MAC_S_C], "hmac-sha1");

    /* Test multiple known MACs */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HMAC_S_C,
                              "hmac-sha1,hmac-sha2-256");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_MAC_S_C]);
    assert_string_equal(bind->wanted_methods[SSH_MAC_S_C],
                        "hmac-sha1,hmac-sha2-256");

    /* Test unknown MACs */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HMAC_S_C,
                              "unknown-crap@example.com,"
                              "hmac-sha1,unknown@example.com");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_MAC_S_C]);
    assert_string_equal(bind->wanted_methods[SSH_MAC_S_C], "hmac-sha1");

    /* Test all unknown MACs */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HMAC_S_C,
                              "unknown-crap@example.com");
    assert_int_not_equal(rc, 0);

    /* Test known MACs */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HMAC_C_S, "hmac-sha1");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_MAC_C_S]);
    assert_string_equal(bind->wanted_methods[SSH_MAC_C_S], "hmac-sha1");

    /* Test multiple known MACs */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HMAC_C_S,
                              "hmac-sha1,hmac-sha2-256");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_MAC_C_S]);
    assert_string_equal(bind->wanted_methods[SSH_MAC_C_S],
                        "hmac-sha1,hmac-sha2-256");

    /* Test unknown MACs */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HMAC_C_S,
                              "unknown-crap@example.com,"
                              "hmac-sha1,unknown@example.com");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_MAC_C_S]);
    assert_string_equal(bind->wanted_methods[SSH_MAC_C_S], "hmac-sha1");

    /* Test all unknown MACs */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HMAC_C_S,
                              "unknown-crap@example.com");
    assert_int_not_equal(rc, 0);
}

static void torture_bind_options_parse_config(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    char *cwd = NULL;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    cwd = torture_get_current_working_dir();
    assert_non_null(cwd);

    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_CONFIG_DIR,
                              (const char *)cwd);
    assert_int_equal(rc, 0);
    assert_non_null(bind->config_dir);
    assert_string_equal(bind->config_dir, cwd);

    rc = ssh_bind_options_parse_config(bind,
                                       "%d/" LIBSSH_CUSTOM_BIND_CONFIG_FILE);
    assert_int_equal(rc, 0);
    assert_int_equal(bind->bindport, 42);

    SAFE_FREE(cwd);
}

static void torture_bind_options_config_dir(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    const char *new_dir = "/new/dir/";
    const char *replacement_dir = "/replacement/dir/";
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_CONFIG_DIR,
                              new_dir);
    assert_int_equal(rc, 0);
    assert_non_null(bind->config_dir);
    assert_string_equal(bind->config_dir, new_dir);

    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_CONFIG_DIR,
                              replacement_dir);
    assert_int_equal(rc, 0);
    assert_non_null(bind->config_dir);
    assert_string_equal(bind->config_dir, replacement_dir);
}

static void torture_bind_options_set_pubkey_accepted_key_types(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    /* Test known Pubkey Types */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES,
                              "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    assert_int_equal(rc, 0);
    assert_non_null(bind->pubkey_accepted_key_types);
    if (ssh_fips_mode()) {
        assert_string_equal(bind->pubkey_accepted_key_types,
                            "ecdsa-sha2-nistp384");
    } else {
        assert_string_equal(bind->pubkey_accepted_key_types,
                            "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    }

    SAFE_FREE(bind->pubkey_accepted_key_types);

    /* Test with some unknown type */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES,
                              "ecdsa-sha2-nistp384,unknown-type,rsa-sha2-256");
    assert_int_equal(rc, 0);
    assert_non_null(bind->pubkey_accepted_key_types);
    assert_string_equal(bind->pubkey_accepted_key_types,
        "ecdsa-sha2-nistp384,rsa-sha2-256");

    SAFE_FREE(bind->pubkey_accepted_key_types);

    /* Test with only unknown type */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES,
                              "unknown-type");
    assert_int_equal(rc, -1);
    assert_null(bind->pubkey_accepted_key_types);

    /* Test with something set and then try unknown type */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES,
                              "ecdsa-sha2-nistp384");
    assert_int_equal(rc, 0);
    assert_non_null(bind->pubkey_accepted_key_types);
    assert_string_equal(bind->pubkey_accepted_key_types, "ecdsa-sha2-nistp384");
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES,
                              "unknown-type");
    assert_int_equal(rc, -1);

    /* Check that nothing changed */
    assert_non_null(bind->pubkey_accepted_key_types);
    assert_string_equal(bind->pubkey_accepted_key_types, "ecdsa-sha2-nistp384");
}

static void torture_bind_options_set_hostkey_algorithms(void **state)
{
    struct bind_st *test_state;
    ssh_bind bind;
    int rc;

    assert_non_null(state);
    test_state = *((struct bind_st **)state);
    assert_non_null(test_state);
    assert_non_null(test_state->bind);
    bind = test_state->bind;

    /* Test known Pubkey Types */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS,
                              "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_HOSTKEYS]);
    if (ssh_fips_mode()) {
        assert_string_equal(bind->wanted_methods[SSH_HOSTKEYS],
                            "ecdsa-sha2-nistp384");
    } else {
        assert_string_equal(bind->wanted_methods[SSH_HOSTKEYS],
                            "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    }

    SAFE_FREE(bind->wanted_methods[SSH_HOSTKEYS]);

    /* Test with some unknown type */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS,
                              "ecdsa-sha2-nistp384,unknown-type");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_HOSTKEYS]);
    assert_string_equal(bind->wanted_methods[SSH_HOSTKEYS],
                        "ecdsa-sha2-nistp384");

    SAFE_FREE(bind->wanted_methods[SSH_HOSTKEYS]);

    /* Test with only unknown type */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS,
                              "unknown-type");
    assert_int_equal(rc, -1);
    assert_null(bind->wanted_methods[SSH_HOSTKEYS]);

    /* Test with something set and then try unknown type */
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS,
                              "ecdsa-sha2-nistp384");
    assert_int_equal(rc, 0);
    assert_non_null(bind->wanted_methods[SSH_HOSTKEYS]);
    assert_string_equal(bind->wanted_methods[SSH_HOSTKEYS],
                        "ecdsa-sha2-nistp384");
    rc = ssh_bind_options_set(bind,
                              SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS,
                              "unknown-type");
    assert_int_equal(rc, -1);

    /* Check that nothing changed */
    assert_non_null(bind->wanted_methods[SSH_HOSTKEYS]);
    assert_string_equal(bind->wanted_methods[SSH_HOSTKEYS],
                        "ecdsa-sha2-nistp384");
}

#endif /* WITH_SERVER */

int
torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_options_set_host,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_host,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_port,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_port,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_fd,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_user,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_user,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_identity,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_identity,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_global_knownhosts,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_global_knownhosts,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_knownhosts,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_knownhosts,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_proxycommand,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_control_master,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_control_path,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_ciphers,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_ciphers,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_key_exchange,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_key_exchange,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_hostkey,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_hostkey,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            torture_options_set_pubkey_accepted_types,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            torture_options_get_pubkey_accepted_types,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_macs,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_macs,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_compression,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_compression,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_copy, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_legacy_integer_values,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_config_host,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_config_match,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_config_match_multi,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_getopt,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_getopt_o_option,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_getopt_quiet,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_getopt_vq,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_getopt_qv,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_getopt_nochange,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_plus_sign,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_minus_sign,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_caret_sign,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_apply, setup, teardown),
        cmocka_unit_test_setup_teardown(
            torture_options_apply_control_path_original_host,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            torture_options_apply_proxycommand_original_host_config,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_verbosity,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_rsa_min_size,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_auth_flags,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_batch_mode,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_escape_char,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_local_forward,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_remote_forward,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_preferred_authentications,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_userauth_list_no_preference,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_userauth_list_filter_subset,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_userauth_list_method_not_supported,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_userauth_list_unknown_method_ignored,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_number_of_password_prompts,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_request_tty,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_send_env,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_int,
                                        setup,
                                        teardown),
    };

#ifdef WITH_SERVER
    struct CMUnitTest sshbind_tests[] = {
        cmocka_unit_test_setup_teardown(torture_bind_options_import_key,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_import_key_str,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_hostkey,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_bindaddr,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_bindport,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_bindport_str,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_log_verbosity,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_log_verbosity_str,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_rsakey,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_set_rsa_min_size,
                                        sshbind_setup,
                                        sshbind_teardown),
#ifdef HAVE_ECC
        cmocka_unit_test_setup_teardown(torture_bind_options_ecdsakey,
                                        sshbind_setup,
                                        sshbind_teardown),
#endif
        cmocka_unit_test_setup_teardown(torture_bind_options_banner,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_set_ciphers,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_set_key_exchange,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_set_macs,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_parse_config,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(torture_bind_options_config_dir,
                                        sshbind_setup,
                                        sshbind_teardown),
        cmocka_unit_test_setup_teardown(
            torture_bind_options_set_pubkey_accepted_key_types,
            sshbind_setup,
            sshbind_teardown),
        cmocka_unit_test_setup_teardown(
            torture_bind_options_set_hostkey_algorithms,
            sshbind_setup,
            sshbind_teardown),
    };
#endif /* WITH_SERVER */

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
#ifdef WITH_SERVER
    rc += cmocka_run_group_tests(sshbind_tests, NULL, NULL);
#endif /* WITH_SERVER */
    ssh_finalize();
    return rc;
}
