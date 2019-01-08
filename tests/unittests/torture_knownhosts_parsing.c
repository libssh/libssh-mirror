#include "config.h"

#include <sys/stat.h>

#define LIBSSH_STATIC
#include <libssh/priv.h>
#include "torture.h"

#include "knownhosts.c"

#if (defined _WIN32) || (defined _WIN64)
#ifndef S_IRWXO
#define S_IRWXO 0
#endif
#ifndef S_IRWXG
#define S_IRWXG 0
#endif
#endif

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
    int rc = 0;

    tmp_file = torture_create_temp_file(TMP_FILE_NAME);
    assert_non_null(tmp_file);

    *state = tmp_file;

    fp = fopen(tmp_file, "w");
    assert_non_null(fp);

    nwritten = fwrite(LOCALHOST_PATTERN_ED25519,
                      sizeof(char),
                      strlen(LOCALHOST_PATTERN_ED25519),
                      fp);
    if (nwritten != strlen(LOCALHOST_PATTERN_ED25519)) {
        rc = -1;
        goto close_fp;
    }

    nwritten = fwrite("\n", sizeof(char), 1, fp);
    if (nwritten != 1) {
        rc = -1;
        goto close_fp;
    }

    nwritten = fwrite(LOCALHOST_RSA_LINE,
                      sizeof(char),
                      strlen(LOCALHOST_RSA_LINE),
                      fp);
    if (nwritten != strlen(LOCALHOST_RSA_LINE)) {
        rc = -1;
        goto close_fp;
    }

close_fp:
    fclose(fp);

    return rc;
}

static int teardown_knownhosts_file(void **state)
{
    char *tmp_file = *state;

    if (tmp_file == NULL) {
        return -1;
    }

    unlink(tmp_file);
    SAFE_FREE(tmp_file);

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

static void torture_knownhosts_read_file(void **state)
{
    const char *knownhosts_file = *state;
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    struct ssh_knownhosts_entry *entry = NULL;
    enum ssh_keytypes_e type;
    int rc;

    rc = ssh_known_hosts_read_entries("localhost",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(entry_list);
    it = ssh_list_get_iterator(entry_list);
    assert_non_null(it);

    /* First key in known hosts file is ED25519 */
    entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
    assert_non_null(entry);

    assert_string_equal(entry->hostname, "localhost");
    type = ssh_key_type(entry->publickey);
    assert_int_equal(type, SSH_KEYTYPE_ED25519);

    it = it->next;

    /* Second key in known hosts file is RSA */
    entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
    assert_non_null(entry);

    assert_string_equal(entry->hostname, "localhost");
    type = ssh_key_type(entry->publickey);
    assert_int_equal(type, SSH_KEYTYPE_RSA);

    it = ssh_list_get_iterator(entry_list);
    for (;it != NULL; it = it->next) {
        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        SSH_KNOWNHOSTS_ENTRY_FREE(entry);
    }
    ssh_list_free(entry_list);
}

static void torture_knownhosts_host_exists(void **state)
{
    const char *knownhosts_file = *state;
    enum ssh_known_hosts_e found;
    ssh_session session;

    session = ssh_new();
    assert_non_null(session);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, knownhosts_file);
    /* This makes sure the system's known_hosts are not used */
    ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, "/dev/null");

    found = ssh_session_has_known_hosts_entry(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);
    assert_true(found == SSH_KNOWN_HOSTS_OK);

    ssh_options_set(session, SSH_OPTIONS_HOST, "wurstbrot");
    found = ssh_session_has_known_hosts_entry(session);
    assert_true(found == SSH_KNOWN_HOSTS_UNKNOWN);

    ssh_free(session);
}

static void torture_knownhosts_host_exists_global(void **state)
{
    const char *knownhosts_file = *state;
    enum ssh_known_hosts_e found;
    ssh_session session;

    session = ssh_new();
    assert_non_null(session);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    /* This makes sure the user's known_hosts are not used */
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, "/dev/null");
    ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, knownhosts_file);

    found = ssh_session_has_known_hosts_entry(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);
    assert_true(found == SSH_KNOWN_HOSTS_OK);

    ssh_options_set(session, SSH_OPTIONS_HOST, "wurstbrot");
    found = ssh_session_has_known_hosts_entry(session);
    assert_true(found == SSH_KNOWN_HOSTS_UNKNOWN);

    ssh_free(session);
}

static void
torture_knownhosts_algorithms(void **state)
{
    const char *knownhosts_file = *state;
    char *algo_list = NULL;
    ssh_session session;
    const char *expect = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa,"
                         "ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,"
                         "ecdsa-sha2-nistp256"
#ifdef HAVE_DSA
                         ",ssh-dss"
#endif
    ;

    session = ssh_new();
    assert_non_null(session);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, knownhosts_file);
    /* This makes sure the system's known_hosts are not used */
    ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, "/dev/null");

    algo_list = ssh_client_select_hostkeys(session);
    assert_non_null(algo_list);
    assert_string_equal(algo_list, expect);
    free(algo_list);

    ssh_free(session);
}

static void
torture_knownhosts_algorithms_global(void **state)
{
    const char *knownhosts_file = *state;
    char *algo_list = NULL;
    ssh_session session;
    const char *expect = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa,"
                         "ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,"
                         "ecdsa-sha2-nistp256"
#ifdef HAVE_DSA
                         ",ssh-dss"
#endif
    ;

    session = ssh_new();
    assert_non_null(session);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    /* This makes sure the current-user's known hosts are not used */
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, "/dev/null");
    ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, knownhosts_file);

    algo_list = ssh_client_select_hostkeys(session);
    assert_non_null(algo_list);
    assert_string_equal(algo_list, expect);
    free(algo_list);

    ssh_free(session);
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
        cmocka_unit_test_setup_teardown(torture_knownhosts_read_file,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_host_exists,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_host_exists_global,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_algorithms,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_algorithms_global,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
