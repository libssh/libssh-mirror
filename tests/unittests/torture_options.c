#include "config.h"

#define LIBSSH_STATIC

#ifndef _WIN32
#define _POSIX_PTHREAD_SEMANTICS
# include <pwd.h>
#endif

#include "torture.h"
#include "torture_key.h"
#include <libssh/session.h>
#include <libssh/misc.h>
#include <libssh/pki_priv.h>
#include <libssh/options.h>

static int setup(void **state)
{
    ssh_session session;
    int verbosity;

    session = ssh_new();

    verbosity = torture_libssh_verbosity();
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

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
    assert_string_equal(session->opts.host, "localhost");

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "guru@meditation");
    assert_true(rc == 0);
    assert_string_equal(session->opts.host, "meditation");
    assert_string_equal(session->opts.username, "guru");
}

static void torture_options_set_ciphers(void **state) {
    ssh_session session = *state;
    int rc;

    /* Test known ciphers */
    rc = ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, "aes128-ctr,aes192-ctr,aes256-ctr");
    assert_true(rc == 0);
    assert_string_equal(session->opts.wanted_methods[SSH_CRYPT_C_S], "aes128-ctr,aes192-ctr,aes256-ctr");

    /* Test one unknown cipher */
    rc = ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, "aes128-ctr,unknown-crap@example.com,aes192-ctr,aes256-ctr");
    assert_true(rc == 0);
    assert_string_equal(session->opts.wanted_methods[SSH_CRYPT_C_S], "aes128-ctr,aes192-ctr,aes256-ctr");

    /* Test all unknown ciphers */
    rc = ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, "unknown-crap@example.com,more-crap@example.com");
    assert_false(rc == 0);
}

static void torture_options_set_key_exchange(void **state)
{
    ssh_session session = *state;
    int rc;

    /* Test known kexes */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_KEY_EXCHANGE,
                         "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha1");
    assert_true(rc == 0);
    assert_string_equal(session->opts.wanted_methods[SSH_KEX],
                        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha1");

    /* Test one unknown kex */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_KEY_EXCHANGE,
                         "curve25519-sha256,curve25519-sha256@libssh.org,unknown-crap@example.com,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha1");
    assert_true(rc == 0);
    assert_string_equal(session->opts.wanted_methods[SSH_KEX],
                        "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha1");

    /* Test all unknown kexes */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_KEY_EXCHANGE,
                         "unknown-crap@example.com,more-crap@example.com");
    assert_false(rc == 0);
}

static void torture_options_set_hostkey(void **state) {
    ssh_session session = *state;
    int rc;

    /* Test known host keys */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HOSTKEYS,
                         "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    assert_true(rc == 0);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");

    /* Test one unknown host key */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HOSTKEYS,
                         "ssh-ed25519,unknown-crap@example.com,ssh-rsa");
    assert_true(rc == 0);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                        "ssh-ed25519,ssh-rsa");

    /* Test all unknown host keys */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HOSTKEYS,
                         "unknown-crap@example.com,more-crap@example.com");
    assert_false(rc == 0);
}

static void torture_options_set_pubkey_accepted_types(void **state) {
    ssh_session session = *state;
    int rc;
    enum ssh_digest_e type;

    /* Test known public key algorithms */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
                         "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");
    assert_true(rc == 0);
    assert_string_equal(session->opts.pubkey_accepted_types,
                        "ssh-ed25519,ecdsa-sha2-nistp384,ssh-rsa");

    /* Test one unknown public key algorithms */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
                         "ssh-ed25519,unknown-crap@example.com,ssh-rsa");
    assert_true(rc == 0);
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

    /* previous configuration did not list the SHA2 extension algoritms, so
     * it should not be used */
    type = ssh_key_type_to_hash(session, SSH_KEYTYPE_RSA);
    assert_int_equal(type, SSH_DIGEST_SHA1);

    /* now, lets allow the signature from SHA2 extension and expect
     * it to be used */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
                         "rsa-sha2-256,ssh-rsa");
    assert_true(rc == 0);
    assert_string_equal(session->opts.pubkey_accepted_types,
                        "rsa-sha2-256,ssh-rsa");
    type = ssh_key_type_to_hash(session, SSH_KEYTYPE_RSA);
    assert_int_equal(type, SSH_DIGEST_SHA256);
}

static void torture_options_set_macs(void **state) {
    ssh_session session = *state;
    int rc;

    /* Test known MACs */
    rc = ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, "hmac-sha1");
    assert_true(rc == 0);
    assert_string_equal(session->opts.wanted_methods[SSH_MAC_S_C], "hmac-sha1");

    /* Test multiple known MACs */
    rc = ssh_options_set(session,
                         SSH_OPTIONS_HMAC_S_C,
                         "hmac-sha1,hmac-sha2-256");
    assert_true(rc == 0);
    assert_string_equal(session->opts.wanted_methods[SSH_MAC_S_C],
                        "hmac-sha1,hmac-sha2-256");

    /* Test unknown MACs */
    rc = ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, "unknown-crap@example.com,hmac-sha1,unknown@example.com");
    assert_true(rc == 0);
    assert_string_equal(session->opts.wanted_methods[SSH_MAC_S_C], "hmac-sha1");

    /* Test all unknown MACs */
    rc = ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, "unknown-crap@example.com");
    assert_false(rc == 0);
}

static void torture_options_get_host(void **state) {
    ssh_session session = *state;
    int rc;
    char* host = NULL;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == 0);
    assert_string_equal(session->opts.host, "localhost");

    assert_false(ssh_options_get(session, SSH_OPTIONS_HOST, &host));

    assert_string_equal(host, "localhost");
    free(host);
}

static void torture_options_set_port(void **state) {
    ssh_session session = *state;
    int rc;
    unsigned int port = 42;

    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    assert_true(rc == 0);
    assert_true(session->opts.port == port);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT_STR, "23");
    assert_true(rc == 0);
    assert_true(session->opts.port == 23);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT_STR, "five");
    assert_true(rc == -1);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT, NULL);
    assert_true(rc == -1);
}

static void torture_options_get_port(void **state) {
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

static void torture_options_get_user(void **state) {
  ssh_session session = *state;
  char* user = NULL;
  int rc;
  rc = ssh_options_set(session, SSH_OPTIONS_USER, "magicaltrevor");
  assert_int_equal(rc, SSH_OK);
  rc = ssh_options_get(session, SSH_OPTIONS_USER, &user);
  assert_int_equal(rc, SSH_OK);
  assert_non_null(user);
  assert_string_equal(user, "magicaltrevor");
  free(user);
}

static void torture_options_set_fd(void **state) {
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

static void torture_options_set_user(void **state) {
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

    rc = ssh_options_set(session, SSH_OPTIONS_USER, "guru");
    assert_true(rc == 0);
    assert_string_equal(session->opts.username, "guru");


    rc = ssh_options_set(session, SSH_OPTIONS_USER, NULL);
    assert_true(rc == 0);

#ifndef _WIN32
    assert_string_equal(session->opts.username, pwd.pw_name);
#endif
}

/* TODO */
#if 0
static voidtorture_options_set_sshdir)
{
}
END_TEST
#endif

static void torture_options_set_identity(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_ADD_IDENTITY, "identity1");
    assert_true(rc == 0);
    assert_string_equal(session->opts.identity->root->data, "identity1");

    rc = ssh_options_set(session, SSH_OPTIONS_IDENTITY, "identity2");
    assert_true(rc == 0);
    assert_string_equal(session->opts.identity->root->data, "identity2");
    assert_string_equal(session->opts.identity->root->next->data, "identity1");
}

static void torture_options_get_identity(void **state) {
    ssh_session session = *state;
    char *identity = NULL;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_ADD_IDENTITY, "identity1");
    assert_true(rc == 0);
    rc = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &identity);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(identity);
    assert_string_equal(identity, "identity1");
    SAFE_FREE(identity);

    rc = ssh_options_set(session, SSH_OPTIONS_IDENTITY, "identity2");
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(session->opts.identity->root->data, "identity2");
    rc = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &identity);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(identity);
    assert_string_equal(identity, "identity2");
    free(identity);
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

static void torture_options_config_host(void **state) {
    ssh_session session = *state;
    FILE *config = NULL;

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

    unlink("test_config");
}

static void torture_options_config_match(void **state)
{
    ssh_session session = *state;
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
    assert_ssh_return_code_equal(session, rv, SSH_ERROR);

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

    /* The Match localuser keyword is ignored */
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

    /* The Match exec keyword is ignored */
    torture_reset_config(session);
    config = fopen("test_config", "w");
    assert_non_null(config);
    fputs("Match exec /bin/true\n"
          "\tPort 33\n"
          "Match all\n"
          "\tPort 34\n",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);
    assert_int_equal(session->opts.port, 34);

    session->opts.port = 0;

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
          "User tester\n"
          "Hostname example.com\n"
          "BindAddress 127.0.0.2\n"
          "GlobalKnownHostsFile /etc/ssh/known_hosts2\n"
          "UserKnownHostsFile ~/.ssh/known_hosts2\n"
          "KexAlgorithms curve25519-sha256\n"
          "Ciphers aes256-ctr\n"
          "MACs hmac-sha2-256\n"
          "HostKeyAlgorithms ssh-ed25519\n"
          "Compression yes\n"
          "PubkeyAcceptedTypes ssh-ed25519\n"
          "ProxyCommand nc 127.0.0.10 22\n"
          /* ops.custombanner */
          "ConnectTimeout 42\n"
          "Port 222\n"
          "StrictHostKeyChecking no\n"
          "GSSAPIServerIdentity my.example.com\n"
          "GSSAPIClientIdentity home.sweet\n"
          "GSSAPIDelegateCredentials yes\n"
          "PubkeyAuthentication yes\n" /* sets flags */
          "GSSAPIAuthentication no\n" /* sets flags */
          "",
          config);
    fclose(config);

    rv = ssh_options_parse_config(session, "test_config");
    assert_ssh_return_code(session, rv);

    rv = ssh_options_copy(session, &new);
    assert_ssh_return_code(session, rv);
    assert_non_null(new);

    /* Check the identities match */
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

    assert_string_equal(session->opts.username, new->opts.username);
    assert_string_equal(session->opts.host, new->opts.host);
    assert_string_equal(session->opts.bindaddr, new->opts.bindaddr);
    assert_string_equal(session->opts.sshdir, new->opts.sshdir);
    assert_string_equal(session->opts.knownhosts, new->opts.knownhosts);
    assert_string_equal(session->opts.global_knownhosts,
                        new->opts.global_knownhosts);
    for (i = 0; i < 10; i++) {
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
    /* TODO custombanner */
    assert_int_equal(session->opts.timeout, new->opts.timeout);
    assert_int_equal(session->opts.timeout_usec, new->opts.timeout_usec);
    assert_int_equal(session->opts.port, new->opts.port);
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
    assert_int_equal(session->opts.flags, new->opts.flags);
    assert_int_equal(session->opts.nodelay, new->opts.nodelay);
    assert_true(session->opts.config_processed == new->opts.config_processed);
    assert_memory_equal(session->opts.options_seen, new->opts.options_seen,
                        sizeof(session->opts.options_seen));

    ssh_free(new);
}



#ifdef WITH_SERVER
/* sshbind options */
static int sshbind_setup(void **state)
{
    ssh_bind bind = ssh_bind_new();
    *state = bind;
    return 0;
}

static int sshbind_teardown(void **state)
{
    ssh_bind_free(*state);
    return 0;
}

static void torture_bind_options_import_key(void **state)
{
    ssh_bind bind = *state;
    int rc;
    const char *base64_key;
    ssh_key key = ssh_key_new();

    /* set null */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, NULL);
    assert_int_equal(rc, -1);
    /* set invalid key */
    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, key);
    assert_int_equal(rc, -1);
    SSH_KEY_FREE(key);

    /* set rsa key */
    base64_key = torture_get_testkey(SSH_KEYTYPE_RSA, 0, 0);
    rc = ssh_pki_import_privkey_base64(base64_key, NULL, NULL, NULL, &key);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(key);

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, key);
    assert_int_equal(rc, 0);
#ifdef HAVE_DSA
    /* set dsa key */
    base64_key = torture_get_testkey(SSH_KEYTYPE_DSS, 0, 0);
    rc = ssh_pki_import_privkey_base64(base64_key, NULL, NULL, NULL, &key);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(key);

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, key);
    assert_int_equal(rc, 0);
#endif
    /* set ecdsa key */
    base64_key = torture_get_testkey(SSH_KEYTYPE_ECDSA, 521, 0);
    rc = ssh_pki_import_privkey_base64(base64_key, NULL, NULL, NULL, &key);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(key);

    rc = ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, key);
    assert_int_equal(rc, 0);
}
#endif /* WITH_SERVER */


int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_options_set_host, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_host, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_port, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_port, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_fd, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_user, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_user, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_identity, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_identity, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_global_knownhosts, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_global_knownhosts, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_knownhosts, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_get_knownhosts, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_proxycommand, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_ciphers, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_key_exchange, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_hostkey, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_pubkey_accepted_types, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_macs, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_copy, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_config_host, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_options_config_match,
                                        setup, teardown)
    };

#ifdef WITH_SERVER
    struct CMUnitTest sshbind_tests[] = {
        cmocka_unit_test_setup_teardown(torture_bind_options_import_key, sshbind_setup, sshbind_teardown),
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
