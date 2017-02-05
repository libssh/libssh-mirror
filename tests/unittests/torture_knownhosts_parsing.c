#include "config.h"

#define LIBSSH_STATIC
#include <libssh/priv.h>
#include "torture.h"

#include "knownhosts.c"

#define LOCALHOST_RSA_LINE "localhost,127.0.0.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDD7g+vV5cvxxGN0Ldmda4WZCPgRaxV1tV+1KRZoGUNUI61h0X4bmmGaAPRQBCz4G1d9bawqDqEqnpFWazrxBU5cQtISSjzuDJKovLGliky/ShTszee1Thszg3qVNk9gGOWj7jn/HDaOxRlp003Bp47MOdnMnK/oftllFDfY2fF5IRpE6sSIGtg2ZDtF95TV5/9W2oMOIAy8u/83tuibYlNPa1X/von5LgdaPLn6Bk16bQKIhAhlMtFZH8MBYEWe4ZtOGaSWKOsK9MM/RTMlwPi6PkfoHNl4MCMupjx+CdLXwbQEt9Ww+bBIaCui2VWBEiruVbIgJh0W2Tal0e2BzYZ What a Wurst!"
#define LOCALHOST_ECDSA_SHA1_NISTP256_LINE "localhost ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFWmI0n0Tn5+zR7pPGcKYszRbJ/T0T3QfzRBSMMiyebGKRY8tjkU5h2l/UMugzOrOyWqMGQDgQn+a0aMunhKMg0="
#define LOCALHOST_DEFAULT_ED25519 "localhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7M22fXD7OiS7kGMXP+OoIjCa+J+5sq8SgAZfIOmDgM"
#define LOCALHOST_PORT_ED25519 "[localhost]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7M22fXD7OiS7kGMXP+OoIjCa+J+5sq8SgAZfIOmDgM"
#define LOCALHOST_PATTERN_ED25519 "local* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7M22fXD7OiS7kGMXP+OoIjCa+J+5sq8SgAZfIOmDgM"
#define LOCALHOST_HASHED_ED25519 "|1|ayWjmTf9mYgj7PuQNVOa7Lqkj5s=|hkbEh8FN6IkLo6t6GQGuBwamgsM= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7M22fXD7OiS7kGMXP+OoIjCa+J+5sq8SgAZfIOmDgM"

#define TMP_FILE_NAME "/tmp/known_hosts_XXXXXX"

static int setup_knownhosts_file(void **state)
{
    char *tmp_file = NULL;
    size_t nwritten;
    FILE *fp = NULL;
    int fd;

    tmp_file = strdup(TMP_FILE_NAME);
    assert_non_null(tmp_file);
    *state = tmp_file;

    fd = mkstemp(tmp_file);
    assert_return_code(fd, errno);

    fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        return -1;
    }

    nwritten = fwrite(LOCALHOST_PATTERN_ED25519,
                      sizeof(char),
                      sizeof(LOCALHOST_PATTERN_ED25519),
                      fp);
    if (nwritten != sizeof(LOCALHOST_PATTERN_ED25519)) {
        fclose(fp);
        return -1;
    }

    nwritten = fwrite(LOCALHOST_RSA_LINE,
                      sizeof(char),
                      sizeof(LOCALHOST_RSA_LINE),
                      fp);
    if (nwritten != sizeof(LOCALHOST_RSA_LINE)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    return 0;
}

static int teardown_knownhosts_file(void **state)
{
    char *tmp_file = *state;

    if (tmp_file == NULL) {
        return -1;
    }

    unlink(tmp_file);

    return 0;
}

static void torture_knownhosts_parse_line_rsa(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_RSA_LINE,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_RSA);
    assert_string_equal(entry->comment, "What a Wurst!");

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);

    rc = ssh_known_hosts_parse_line("127.0.0.1",
                                    LOCALHOST_RSA_LINE,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "127.0.0.1");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_RSA);
    assert_string_equal(entry->comment, "What a Wurst!");

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_ecdsa(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_ECDSA_SHA1_NISTP256_LINE,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ECDSA);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_default_ed25519(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_DEFAULT_ED25519,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ED25519);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_port_ed25519(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("[localhost]:2222",
                                    LOCALHOST_PORT_ED25519,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "[localhost]:2222");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ED25519);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_pattern_ed25519(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_PATTERN_ED25519,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ED25519);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_hashed_ed25519(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_HASHED_ED25519,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ED25519);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_knownhosts_parse_line_rsa),
        cmocka_unit_test(torture_knownhosts_parse_line_ecdsa),
        cmocka_unit_test(torture_knownhosts_parse_line_default_ed25519),
        cmocka_unit_test(torture_knownhosts_parse_line_port_ed25519),
        cmocka_unit_test(torture_knownhosts_parse_line_pattern_ed25519),
        cmocka_unit_test(torture_knownhosts_parse_line_hashed_ed25519),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
