#include "config.h"

#include <limits.h>

#define LIBSSH_STATIC

#ifndef _WIN32
#define _POSIX_PTHREAD_SEMANTICS
#include <pwd.h>
#endif

#include "torture.h"
#include "libssh/options.h"
#include "libssh/session.h"
#include "libssh/config_parser.h"
#include "match.c"
#include "config.c"
#include "libssh/socket.h"
#include "libssh/misc.h"

extern LIBSSH_THREAD int ssh_log_level;

#define USERNAME "testuser"
#define PROXYCMD "ssh -q -W %h:%p gateway.example.com"
#define ID_FILE "/etc/xxx"
#define KEXALGORITHMS "ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha1"
#define HOSTKEYALGORITHMS "ssh-ed25519,ecdsa-sha2-nistp521,ssh-rsa"
#define PUBKEYACCEPTEDTYPES "rsa-sha2-512,ssh-rsa,ecdsa-sha2-nistp521"
#define MACS "hmac-sha1,hmac-sha2-256,hmac-sha2-512,hmac-sha1-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"
#define USER_KNOWN_HOSTS "%d/.ssh/my_known_hosts"
#define GLOBAL_KNOWN_HOSTS "/etc/ssh/my_ssh_known_hosts"
#define BIND_ADDRESS "::1"


#define LIBSSH_TESTCONFIG1 "libssh_testconfig1.tmp"
#define LIBSSH_TESTCONFIG2 "libssh_testconfig2.tmp"
#define LIBSSH_TESTCONFIG3 "libssh_testconfig3.tmp"
#define LIBSSH_TESTCONFIG4 "libssh_testconfig4.tmp"
#define LIBSSH_TESTCONFIG5 "libssh_testconfig5.tmp"
#define LIBSSH_TESTCONFIG6 "libssh_testconfig6.tmp"
#define LIBSSH_TESTCONFIG7 "libssh_testconfig7.tmp"
#define LIBSSH_TESTCONFIG8 "libssh_testconfig8.tmp"
#define LIBSSH_TESTCONFIG9 "libssh_testconfig9.tmp"
#define LIBSSH_TESTCONFIG10 "libssh_testconfig10.tmp"
#define LIBSSH_TESTCONFIG11 "libssh_testconfig11.tmp"
#define LIBSSH_TESTCONFIG12 "libssh_testconfig12.tmp"
#define LIBSSH_TESTCONFIG14 "libssh_testconfig14.tmp"
#define LIBSSH_TESTCONFIG15 "libssh_testconfig15.tmp"
#define LIBSSH_TESTCONFIG16 "libssh_testconfig16.tmp"
#define LIBSSH_TESTCONFIG17 "libssh_testconfig17.tmp"
#define LIBSSH_TESTCONFIG18 "libssh_testconfig18.tmp"
#define LIBSSH_TESTCONFIG19 "libssh_testconfig19.tmp"
#define LIBSSH_TESTCONFIG21 "libssh_testconfig21.tmp"
#define LIBSSH_TESTCONFIG22 "libssh_testconfig22.tmp"
#define LIBSSH_TESTCONFIG24 "libssh_testconfig24.tmp"
#define LIBSSH_TESTCONFIG25 "libssh_testconfig25.tmp"
/*
 * The glob pattern below matches 3 or 6 as the last character before .tmp,
 * so test config filenames ending with 3 or 6 (for example,
 * libssh_testconfig13.tmp, libssh_testconfig23.tmp) would collide with the
 * glob include test and will fail. Numbers ending with 3 and 6 are therefore
 * intentionally skipped when adding new test configuration files.
 */
#define LIBSSH_TESTCONFIG27 "libssh_testconfig27.tmp"
#define LIBSSH_TESTCONFIG28 "libssh_testconfig28.tmp"
#define LIBSSH_TESTCONFIG30 "libssh_testconfig30.tmp"
#define LIBSSH_TESTCONFIG31 "libssh_testconfig31.tmp"
#define LIBSSH_TESTCONFIGGLOB "libssh_testc*[36].tmp"
#define LIBSSH_TEST_PUBKEYTYPES "libssh_test_PubkeyAcceptedKeyTypes.tmp"
#define LIBSSH_TEST_PUBKEYALGORITHMS "libssh_test_PubkeyAcceptedAlgorithms.tmp"
#define LIBSSH_TEST_NONEWLINEEND "libssh_test_NoNewLineEnd.tmp"
#define LIBSSH_TEST_NONEWLINEONELINE "libssh_test_NoNewLineOneline.tmp"
#define LIBSSH_TEST_RECURSIVE_INCLUDE "libssh_test_recursive_include.tmp"
#define LIBSSH_TESTCONFIG_MATCH_COMPLEX "libssh_test_match_complex.tmp"
#define LIBSSH_TESTCONFIG_LOGLEVEL_MISSING "libssh_test_loglevel_missing.tmp"
#define LIBSSH_TESTCONFIG_JUMP "libssh_test_jump.tmp"
#define LIBSSH_TESTCONFIG_NUMERIC_INVALID  "libssh_test_numeric_invalid.tmp"
#define LIBSSH_TESTCONFIG_TIMEOUT_SUFFIX   "libssh_test_timeout_suffix.tmp"
#define LIBSSH_TESTCONFIG_BOOLEAN_INVALID  "libssh_test_boolean_invalid.tmp"
#define LIBSSH_TESTCONFIG_BOOLEAN_COMPAT   "libssh_test_boolean_compat.tmp"
#define LIBSSH_TESTCONFIG29 "libssh_testconfig29.tmp"
#define LIBSSH_TESTCONFIG32 "libssh_testconfig32.tmp"

#define LIBSSH_TESTCONFIG_STRING1 \
    "User "USERNAME"\nInclude "LIBSSH_TESTCONFIG2"\n\n"

#define LIBSSH_TESTCONFIG_STRING2 \
    "Include "LIBSSH_TESTCONFIG3"\n" \
    "ProxyCommand "PROXYCMD"\n\n"

#define LIBSSH_TESTCONFIG_STRING3 \
    "\n\nIdentityFile "ID_FILE"\n" \
    "\n\nKexAlgorithms "KEXALGORITHMS"\n" \
    "\n\nHostKeyAlgorithms "HOSTKEYALGORITHMS"\n" \
    "\n\nPubkeyAcceptedAlgorithms "PUBKEYACCEPTEDTYPES"\n" \
    "\n\nMACs "MACS"\n"

/* Multiple Port settings -> parsing returns early. */
#define LIBSSH_TESTCONFIG_STRING4 \
   "Port 123\nPort 456\n"

/* Testing glob include */
#define LIBSSH_TESTCONFIG_STRING5 \
    "User "USERNAME"\nInclude "LIBSSH_TESTCONFIGGLOB"\n\n" \

#define LIBSSH_TESTCONFIG_STRING6 \
    "ProxyCommand "PROXYCMD"\n\n"

/* new options */
#define LIBSSH_TESTCONFIG_STRING7 \
    "\tBindAddress "BIND_ADDRESS"\n" \
    "\tConnectTimeout 30\n" \
    "\tLogLevel DEBUG3\n" \
    "\tGlobalKnownHostsFile "GLOBAL_KNOWN_HOSTS"\n" \
    "\tCompression yes\n" \
    "\tStrictHostkeyChecking no\n" \
    "\tGSSAPIDelegateCredentials yes\n" \
    "\tGSSAPIServerIdentity example.com\n" \
    "\tGSSAPIClientIdentity home.sweet\n" \
    "\tUserKnownHostsFile "USER_KNOWN_HOSTS"\n" \
    "\tRequiredRSASize 2233\n" \
    "\tGSSAPIKeyExchange yes\n" \
    "\tGSSAPIKexAlgorithms gss-group14-sha256-\n"

/* authentication methods */
#define LIBSSH_TESTCONFIG_STRING8 \
    "Host gss\n" \
    "\tGSSAPIAuthentication yes\n" \
    "Host challenge\n" \
    "\tChallengeResponseAuthentication yes\n" \
    "Host kbd\n" \
    "\tKbdInteractiveAuthentication yes\n" \
    "Host pass\n" \
    "\tPasswordAuthentication yes\n" \
    "Host pubkey\n" \
    "\tPubkeyAuthentication yes\n" \
    "Host nogss\n" \
    "\tGSSAPIAuthentication no\n" \
    "Host nochallenge\n" \
    "\tChallengeResponseAuthentication no\n" \
    "Host nokbd\n" \
    "\tKbdInteractiveAuthentication no\n" \
    "Host nopass\n" \
    "\tPasswordAuthentication no\n" \
    "Host nopubkey\n" \
    "\tPubkeyAuthentication no\n"

/* unsupported options and corner cases */
#define LIBSSH_TESTCONFIG_STRING9 \
    "\n" /* empty line */ \
    "# comment line\n" \
    "  # comment line not starting with hash\n" \
    "UnknownConfigurationOption yes\n" \
    "GSSAPIKexAlgorithms yes\n" \
    "ControlMaster auto\n" /* SOC_NA */ \
    "VisualHostkey yes\n" /* SOC_UNSUPPORTED */ \
    "HostName =equal.sign\n" /* valid */ \
    "ProxyJump = many-spaces.com\n" /* valid */

/* Match keyword */
#define LIBSSH_TESTCONFIG_STRING10       \
    "Match host example\n"               \
    "\tHostName example.com\n"           \
    "Match host example1,example2\n"     \
    "\tHostName exampleN\n"              \
    "Match user guest\n"                 \
    "\tHostName guest.com\n"             \
    "Match user tester host testhost\n"  \
    "\tHostName testhost.com\n"          \
    "Match !user tester host testhost\n" \
    "\tHostName nonuser-testhost.com\n"  \
    "Match all\n"                        \
    "\tHostName all-matched.com\n"       \
    "Match originalhost example\n"       \
    "\tHostName original-example.com\n"  \
    "\tUser originaluser\n"              \
    "Match localuser guest\n"            \
    "\tHostName local-guest.com\n"

/* ProxyJump */
#define LIBSSH_TESTCONFIG_STRING11 \
    "Host simple\n" \
    "\tProxyJump jumpbox\n" \
    "Host user\n" \
    "\tProxyJump user@jumpbox\n" \
    "Host port\n" \
    "\tProxyJump jumpbox:2222\n" \
    "Host two-step\n" \
    "\tProxyJump u1@first:222,u2@second:33\n" \
    "Host three-step\n" \
    "\tProxyJump u1@first:222,u2@second:33,u3@third:444\n" \
    "Host none\n" \
    "\tProxyJump none\n" \
    "Host only-command\n" \
    "\tProxyCommand "PROXYCMD"\n" \
    "\tProxyJump jumpbox\n" \
    "Host only-jump\n" \
    "\tProxyJump jumpbox\n" \
    "\tProxyCommand "PROXYCMD"\n" \
    "Host ipv6\n" \
    "\tProxyJump [2620:52:0::fed]\n"

/* RekeyLimit combinations */
#define LIBSSH_TESTCONFIG_STRING12 \
    "Host default\n" \
    "\tRekeyLimit default none\n" \
    "Host data1\n" \
    "\tRekeyLimit 42G\n" \
    "Host datatime\n" \
    "\tRekeyLimit 42G 1h\n" \
    "Host data2\n" \
    "\tRekeyLimit 31M\n" \
    "Host data3\n" \
    "\tRekeyLimit 521K\n" \
    "Host data4\n" \
    "\tRekeyLimit 5k*n\n" \
    "Host time1\n" \
    "\tRekeyLimit default 3D\n" \
    "Host time2\n" \
    "\tRekeyLimit default 2h\n" \
    "Host time3\n" \
    "\tRekeyLimit default 160m\n" \
    "Host time4\n" \
    "\tRekeyLimit default 9600\n"

/* Multiple IdentityFile settings all are applied */
#define LIBSSH_TESTCONFIG_STRING13 \
   "IdentityFile id_rsa_one\n" \
   "CertificateFile id_rsa_one-cert.pub\n" \
   "IdentityFile id_ecdsa_two\n" \
   "CertificateFile id_ecdsa_two-cert.pub\n" \

/* +,-,^ features for all supported list */
/* kex won't work in fips */
#define LIBSSH_TESTCONFIG_STRING14 \
    "HostKeyAlgorithms +ssh-rsa\n" \
    "Ciphers +aes128-cbc,aes256-cbc\n" \
    "KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group1-sha1\n" \
    "MACs +hmac-sha1,hmac-sha1-etm@openssh.com\n"

/* have to be algorithms which are in the default list */
#define LIBSSH_TESTCONFIG_STRING15 \
    "HostKeyAlgorithms -rsa-sha2-512,rsa-sha2-256\n" \
    "Ciphers -aes256-ctr\n" \
    "KexAlgorithms -diffie-hellman-group18-sha512,diffie-hellman-group16-sha512\n" \
    "MACs -hmac-sha2-256-etm@openssh.com\n"

#define LIBSSH_TESTCONFIG_STRING16 \
    "HostKeyAlgorithms ^rsa-sha2-512,rsa-sha2-256\n" \
    "Ciphers ^aes256-cbc\n" \
    "KexAlgorithms ^diffie-hellman-group18-sha512,diffie-hellman-group16-sha512\n" \
    "MACs ^hmac-sha1\n"

/* Connection Multiplexing */
#define LIBSSH_TESTCONFIG_STRING17 \
    "Host simple\n" \
    "\tControlMaster auto\n" \
    "\tControlPath /tmp/ssh-%r@%h:%p\n" \
    "Host none\n" \
    "\tControlMaster yes\n" \
    "\tControlPath none\n"

#define LIBSSH_TESTCONFIG_STRING18 \
    "Host simple\n"                \
    "Host af\n"                    \
    "\tAddressFamily any\n"        \
    "Host af4\n"                   \
    "\tAddressFamily inet\n"       \
    "Host af6\n"                   \
    "\tAddressFamily inet6\n"

#define LIBSSH_TESTCONFIG_STRING19 \
    "Host nobatch\n"               \
    "\tBatchMode no\n"             \
    "Host batch\n"                 \
    "\tBatchMode yes\n"

#define LIBSSH_TESTCONFIG20 "libssh_testconfig20.tmp"
#define LIBSSH_TESTCONFIG_STRING20                    \
    "Host withpref\n"                                 \
    "\tPreferredAuthentications publickey,password\n" \
    "Host nopref\n"                                   \
    "\tHostName example.com\n"

#define LIBSSH_TESTCONFIG_STRING21  \
    "Host fewprompts\n"             \
    "\tNumberOfPasswordPrompts 1\n" \
    "Host defaultprompts\n"         \
    "\tHostName example.com\n"
#define LIBSSH_TESTCONFIG_STRING22 \
    "Host notty\n"                 \
    "\tRequestTTY no\n"            \
    "Host ttyyes\n"                \
    "\tRequestTTY yes\n"           \
    "Host ttyauto\n"               \
    "\tRequestTTY auto\n"          \
    "Host ttyforce\n"              \
    "\tRequestTTY force\n"

#define LIBSSH_TESTCONFIG_STRING24 \
    "Host tildeescape\n"           \
    "\tEscapeChar ~\n"             \
    "Host ctrlcescape\n"           \
    "\tEscapeChar ^C\n"            \
    "Host noescape\n"              \
    "\tEscapeChar none\n"
#define LIBSSH_TESTCONFIG_STRING25 \
    "Host withenv\n"               \
    "\tSendEnv LANG LC_*\n"        \
    "\tSendEnv TZ\n"               \
    "Host noenv\n"                 \
    "\tHostName example.com\n"     \
    "Host negenv\n"                \
    "\tSendEnv LANG LC_*\n"        \
    "\tSendEnv TZ\n"               \
    "\tSendEnv -LANG\n"

#define LIBSSH_TESTCONFIG_STRING27                      \
    "Host withfwd\n"                                    \
    "\tLocalForward 8080 web:80\n"                      \
    "\tLocalForward 0.0.0.0:9090 db:3306\n"             \
    "\tLocalForward /tmp/local.sock /tmp/remote.sock\n" \
    "Host nofwd\n"                                      \
    "\tHostName example.com\n"

#define LIBSSH_TESTCONFIG_STRING28                      \
    "Host withrfwd\n"                                   \
    "\tRemoteForward 8080 web:80\n"                     \
    "\tRemoteForward 0.0.0.0:9090 db:3306\n"            \
    "\tRemoteForward /tmp/remote.sock /tmp/local.sock\n"\
    "Host norfwd\n"                                     \
    "\tHostName example.com\n"

#define LIBSSH_TESTCONFIG_STRING29 \
    "Host exit_fwd_no\n"            \
    "\tExitOnForwardFailure no\n"   \
    "Host exit_fwd_yes\n"           \
    "\tExitOnForwardFailure yes\n"

#define LIBSSH_TESTCONFIG_STRING30 \
    "Host shortinterval\n"         \
    "\tServerAliveInterval 10\n"   \
    "Host longinterval\n"          \
    "\tServerAliveInterval 300\n"  \
    "Host defaultinterval\n"       \
    "\tHostName example.com\n"

#define LIBSSH_TESTCONFIG_STRING31 \
    "Host lowcount\n"              \
    "\tServerAliveCountMax 1\n"    \
    "Host highcount\n"             \
    "\tServerAliveCountMax 10\n"   \
    "Host defaultcount\n"          \
    "\tHostName example.com\n"

#define LIBSSH_TESTCONFIG_STRING32     \
    "Host fwd_no\n"                    \
    "\tForwardAgent no\n"              \
    "Host fwd_yes\n"                   \
    "\tForwardAgent yes\n"             \
    "Host fwd_sock\n"                  \
    "\tForwardAgent /tmp/agent.sock\n" \
    "Host fwd_env\n"                   \
    "\tForwardAgent $SSH_AUTH_SOCK\n"  \
    "Host fwd_true\n"                  \
    "\tForwardAgent true\n"            \
    "Host fwd_false\n"                 \
    "\tForwardAgent false\n"

#define LIBSSH_TEST_PUBKEYTYPES_STRING \
    "PubkeyAcceptedKeyTypes "PUBKEYACCEPTEDTYPES"\n"

#define LIBSSH_TEST_PUBKEYALGORITHMS_STRING \
    "PubkeyAcceptedAlgorithms "PUBKEYACCEPTEDTYPES"\n"

#define LIBSSH_TEST_NONEWLINEEND_STRING \
    "ConnectTimeout 30\n" \
    "LogLevel DEBUG3"

#define LIBSSH_TEST_NONEWLINEONELINE_STRING \
    "ConnectTimeout 30"

#define LIBSSH_TEST_RECURSIVE_INCLUDE_STRING \
    "Include " LIBSSH_TEST_RECURSIVE_INCLUDE

/* Complex match cases */
#define LIBSSH_TESTCONFIG_MATCH_COMPLEX_STRING \
    "Match originalhost \"Foo,Bar\" exec \"[ \\\"$(ps h o comm p $(ps h o ppid p $PPID))\\\" != \\\"rsync\\\" ]\"\n" \
    "Match exec \"[ \\\"$(ps h o comm p $(ps h o ppid p $PPID))\\\" != \\\"rsync\\\" ]\"\n" \
    "\tForwardAgent yes\n" \
    "\tHostName complex-match\n"

#define LIBSSH_TESTCONFIG_LOGLEVEL_MISSING_STRING "LogLevel\n"
#define LIBSSH_TESTCONFIG_JUMP_STRING \
    "# The jump host\n" \
    "Host ub-jumphost\n" \
    "    HostName 1xxxxxx\n" \
    "    User ubuntu\n" \
    "    IdentityFile ~/of/temp-libssh.pem\n" \
    "    Port 23\n" \
    "    LogLevel DEBUG3\n" \
    "\n" \
    "# Cisco Router through Jump Host\n" \
    "Host cisco-router\n" \
    "    HostName xx.xxxxxxxxx\n" \
    "    User username\n" \
    "    ProxyJump ub-jumphost\n" \
    "    Port 5555\n" \
    "    #RequiredRSASize 512\n" \
    "    PasswordAuthentication yes\n" \
    "    LogLevel DEBUG3\n"

/**
 * @brief helper function loading configuration from either file or string
 */
static void _parse_config(ssh_session session,
                          const char *file, const char *string, int expected)
{
    int ret = -1;

    /* make sure either config file or config string is given,
     * not both */
    assert_int_not_equal(file == NULL, string == NULL);

    if (file != NULL) {
        ret = ssh_config_parse_file(session, file);
    } else if (string != NULL) {
        ret = ssh_config_parse_string(session, string);
    } else {
        /* should not happen */
        fail();
    }

    /* make sure parsing went as expected */
    assert_ssh_return_code_equal(session, ret, expected);
}

static int setup_config_files(void **state)
{
    (void) state; /* unused */

    unlink(LIBSSH_TESTCONFIG1);
    unlink(LIBSSH_TESTCONFIG2);
    unlink(LIBSSH_TESTCONFIG3);
    unlink(LIBSSH_TESTCONFIG4);
    unlink(LIBSSH_TESTCONFIG5);
    unlink(LIBSSH_TESTCONFIG6);
    unlink(LIBSSH_TESTCONFIG7);
    unlink(LIBSSH_TESTCONFIG8);
    unlink(LIBSSH_TESTCONFIG9);
    unlink(LIBSSH_TESTCONFIG10);
    unlink(LIBSSH_TESTCONFIG11);
    unlink(LIBSSH_TESTCONFIG12);
    unlink(LIBSSH_TESTCONFIG14);
    unlink(LIBSSH_TESTCONFIG15);
    unlink(LIBSSH_TESTCONFIG16);
    unlink(LIBSSH_TESTCONFIG17);
    unlink(LIBSSH_TESTCONFIG18);
    unlink(LIBSSH_TESTCONFIG19);
    unlink(LIBSSH_TESTCONFIG21);
    unlink(LIBSSH_TESTCONFIG22);
    unlink(LIBSSH_TESTCONFIG24);
    unlink(LIBSSH_TESTCONFIG25);
    unlink(LIBSSH_TESTCONFIG27);
    unlink(LIBSSH_TESTCONFIG28);
    unlink(LIBSSH_TESTCONFIG29);
    unlink(LIBSSH_TESTCONFIG30);
    unlink(LIBSSH_TESTCONFIG31);
    unlink(LIBSSH_TESTCONFIG32);
    unlink(LIBSSH_TEST_PUBKEYTYPES);
    unlink(LIBSSH_TEST_PUBKEYALGORITHMS);
    unlink(LIBSSH_TEST_NONEWLINEEND);
    unlink(LIBSSH_TEST_NONEWLINEONELINE);
    unlink(LIBSSH_TESTCONFIG_MATCH_COMPLEX);
    unlink(LIBSSH_TESTCONFIG_LOGLEVEL_MISSING);
    unlink(LIBSSH_TESTCONFIG_JUMP);
    unlink(LIBSSH_TESTCONFIG_NUMERIC_INVALID);
    unlink(LIBSSH_TESTCONFIG_TIMEOUT_SUFFIX);
    unlink(LIBSSH_TESTCONFIG_BOOLEAN_INVALID);
    unlink(LIBSSH_TESTCONFIG_BOOLEAN_COMPAT);
    unlink(LIBSSH_TESTCONFIG20);

    torture_write_file(LIBSSH_TESTCONFIG1,
                       LIBSSH_TESTCONFIG_STRING1);
    torture_write_file(LIBSSH_TESTCONFIG2,
                       LIBSSH_TESTCONFIG_STRING2);
    torture_write_file(LIBSSH_TESTCONFIG3,
                       LIBSSH_TESTCONFIG_STRING3);

    /* Multiple Port settings -> parsing returns early. */
    torture_write_file(LIBSSH_TESTCONFIG4,
                       LIBSSH_TESTCONFIG_STRING4);

    /* Testing glob include */
    torture_write_file(LIBSSH_TESTCONFIG5,
                       LIBSSH_TESTCONFIG_STRING5);

    torture_write_file(LIBSSH_TESTCONFIG6,
                       LIBSSH_TESTCONFIG_STRING6);

    /* new options */
    torture_write_file(LIBSSH_TESTCONFIG7,
                       LIBSSH_TESTCONFIG_STRING7);

    /* authentication methods */
    torture_write_file(LIBSSH_TESTCONFIG8,
                       LIBSSH_TESTCONFIG_STRING8);

    /* unsupported options and corner cases */
    torture_write_file(LIBSSH_TESTCONFIG9,
                       LIBSSH_TESTCONFIG_STRING9);

    /* Match keyword */
    torture_write_file(LIBSSH_TESTCONFIG10,
                       LIBSSH_TESTCONFIG_STRING10);

    /* ProxyJump */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       LIBSSH_TESTCONFIG_STRING11);

    /* RekeyLimit combinations */
    torture_write_file(LIBSSH_TESTCONFIG12,
                       LIBSSH_TESTCONFIG_STRING12);

    /* +,-,^ feature */
    torture_write_file(LIBSSH_TESTCONFIG14,
                       LIBSSH_TESTCONFIG_STRING14);
    torture_write_file(LIBSSH_TESTCONFIG15,
                       LIBSSH_TESTCONFIG_STRING15);
    torture_write_file(LIBSSH_TESTCONFIG16,
                       LIBSSH_TESTCONFIG_STRING16);
    torture_write_file(LIBSSH_TESTCONFIG17,
                       LIBSSH_TESTCONFIG_STRING17);
    torture_write_file(LIBSSH_TESTCONFIG18,
                       LIBSSH_TESTCONFIG_STRING18);

    /* BatchMode */
    torture_write_file(LIBSSH_TESTCONFIG19,
                       LIBSSH_TESTCONFIG_STRING19);

    /* NumberOfPasswordPrompts */
    torture_write_file(LIBSSH_TESTCONFIG21,
                       LIBSSH_TESTCONFIG_STRING21);
    /* RequestTTY */
    torture_write_file(LIBSSH_TESTCONFIG22,
                       LIBSSH_TESTCONFIG_STRING22);
    /* EscapeChar */
    torture_write_file(LIBSSH_TESTCONFIG24,
                       LIBSSH_TESTCONFIG_STRING24);
    /* ServerAliveInterval */
    torture_write_file(LIBSSH_TESTCONFIG30,
                       LIBSSH_TESTCONFIG_STRING30);
    /* ServerAliveCountMax */
    torture_write_file(LIBSSH_TESTCONFIG31,
                       LIBSSH_TESTCONFIG_STRING31);
    /* LocalForward */
    torture_write_file(LIBSSH_TESTCONFIG27,
                       LIBSSH_TESTCONFIG_STRING27);
    /* RemoteForward */
    torture_write_file(LIBSSH_TESTCONFIG28,
                       LIBSSH_TESTCONFIG_STRING28);
    /* ExitOnForwardFailure */
    torture_write_file(LIBSSH_TESTCONFIG29,
                       LIBSSH_TESTCONFIG_STRING29);
    /* ForwardAgent */
    torture_write_file(LIBSSH_TESTCONFIG32,
                       LIBSSH_TESTCONFIG_STRING32);
    /* SendEnv */
    torture_write_file(LIBSSH_TESTCONFIG25,
                       LIBSSH_TESTCONFIG_STRING25);

    torture_write_file(LIBSSH_TEST_PUBKEYTYPES,
                       LIBSSH_TEST_PUBKEYTYPES_STRING);

    torture_write_file(LIBSSH_TEST_PUBKEYALGORITHMS,
                       LIBSSH_TEST_PUBKEYALGORITHMS_STRING);

    torture_write_file(LIBSSH_TEST_NONEWLINEEND,
                       LIBSSH_TEST_NONEWLINEEND_STRING);

    torture_write_file(LIBSSH_TEST_NONEWLINEONELINE,
                       LIBSSH_TEST_NONEWLINEONELINE_STRING);

    /* Match complex combinations */
    torture_write_file(LIBSSH_TESTCONFIG_MATCH_COMPLEX,
                       LIBSSH_TESTCONFIG_MATCH_COMPLEX_STRING);
    torture_write_file(LIBSSH_TESTCONFIG_LOGLEVEL_MISSING,
                       LIBSSH_TESTCONFIG_LOGLEVEL_MISSING_STRING);
    torture_write_file(LIBSSH_TESTCONFIG_JUMP,
                       LIBSSH_TESTCONFIG_JUMP_STRING);

    /* PreferredAuthentications */
    torture_write_file(LIBSSH_TESTCONFIG20,
                       LIBSSH_TESTCONFIG_STRING20);

    return 0;
}

static int teardown_config_files(void **state)
{
    (void) state; /* unused */

    unlink(LIBSSH_TESTCONFIG1);
    unlink(LIBSSH_TESTCONFIG2);
    unlink(LIBSSH_TESTCONFIG3);
    unlink(LIBSSH_TESTCONFIG4);
    unlink(LIBSSH_TESTCONFIG5);
    unlink(LIBSSH_TESTCONFIG6);
    unlink(LIBSSH_TESTCONFIG7);
    unlink(LIBSSH_TESTCONFIG8);
    unlink(LIBSSH_TESTCONFIG9);
    unlink(LIBSSH_TESTCONFIG10);
    unlink(LIBSSH_TESTCONFIG11);
    unlink(LIBSSH_TESTCONFIG12);
    unlink(LIBSSH_TESTCONFIG14);
    unlink(LIBSSH_TESTCONFIG15);
    unlink(LIBSSH_TESTCONFIG16);
    unlink(LIBSSH_TESTCONFIG17);
    unlink(LIBSSH_TESTCONFIG18);
    unlink(LIBSSH_TESTCONFIG19);
    unlink(LIBSSH_TESTCONFIG21);
    unlink(LIBSSH_TESTCONFIG22);
    unlink(LIBSSH_TESTCONFIG24);
    unlink(LIBSSH_TESTCONFIG25);
    unlink(LIBSSH_TESTCONFIG27);
    unlink(LIBSSH_TESTCONFIG28);
    unlink(LIBSSH_TESTCONFIG29);
    unlink(LIBSSH_TESTCONFIG30);
    unlink(LIBSSH_TESTCONFIG31);
    unlink(LIBSSH_TESTCONFIG32);
    unlink(LIBSSH_TEST_PUBKEYTYPES);
    unlink(LIBSSH_TEST_PUBKEYALGORITHMS);
    unlink(LIBSSH_TEST_NONEWLINEEND);
    unlink(LIBSSH_TEST_NONEWLINEONELINE);
    unlink(LIBSSH_TESTCONFIG_MATCH_COMPLEX);
    unlink(LIBSSH_TESTCONFIG_LOGLEVEL_MISSING);
    unlink(LIBSSH_TESTCONFIG_JUMP);
    unlink(LIBSSH_TESTCONFIG_NUMERIC_INVALID);
    unlink(LIBSSH_TESTCONFIG_TIMEOUT_SUFFIX);
    unlink(LIBSSH_TESTCONFIG_BOOLEAN_INVALID);
    unlink(LIBSSH_TESTCONFIG_BOOLEAN_COMPAT);
    unlink(LIBSSH_TESTCONFIG20);

    return 0;
}

static int setup(void **state)
{
    ssh_session session = NULL;
    char *wd = NULL;
    int verbosity;

    session = ssh_new();

    verbosity = torture_libssh_verbosity();
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    wd = torture_get_current_working_dir();
    ssh_options_set(session, SSH_OPTIONS_SSH_DIR, wd);
    free(wd);

    *state = session;

    return 0;
}

static int setup_no_sshdir(void **state)
{
    ssh_session session = NULL;
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

/**
 * @brief tests ssh config parsing with Include directives
 */
static void torture_config_include(void **state,
                                   const char *file, const char *string)
{
    int ret;
    char *v = NULL;
    char *fips_algos = NULL;
    ssh_session session = *state;

    _parse_config(session, file, string, SSH_OK);

    /* Test the variable presence */
    ret = ssh_options_get(session, SSH_OPTIONS_PROXYCOMMAND, &v);
    assert_true(ret == 0);
    assert_non_null(v);

    assert_string_equal(v, PROXYCMD);
    SSH_STRING_FREE_CHAR(v);

    ret = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &v);
    assert_true(ret == 0);
    assert_non_null(v);

    assert_string_equal(v, ID_FILE);
    SSH_STRING_FREE_CHAR(v);

    ret = ssh_options_get(session, SSH_OPTIONS_USER, &v);
    assert_true(ret == 0);
    assert_non_null(v);

    assert_string_equal(v, USERNAME);
    SSH_STRING_FREE_CHAR(v);

    if (ssh_fips_mode()) {
        fips_algos = ssh_keep_fips_algos(SSH_KEX, KEXALGORITHMS);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.wanted_methods[SSH_KEX], fips_algos);
        SAFE_FREE(fips_algos);
        fips_algos = ssh_keep_fips_algos(SSH_HOSTKEYS, HOSTKEYALGORITHMS);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                fips_algos);
        SAFE_FREE(fips_algos);
        fips_algos = ssh_keep_fips_algos(SSH_HOSTKEYS, PUBKEYACCEPTEDTYPES);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.pubkey_accepted_types, fips_algos);
        SAFE_FREE(fips_algos);
        fips_algos = ssh_keep_fips_algos(SSH_MAC_C_S, MACS);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.wanted_methods[SSH_MAC_C_S],
                fips_algos);
        SAFE_FREE(fips_algos);
        fips_algos = ssh_keep_fips_algos(SSH_MAC_S_C, MACS);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.wanted_methods[SSH_MAC_S_C],
                fips_algos);
        SAFE_FREE(fips_algos);
    } else {
        assert_non_null(session->opts.wanted_methods[SSH_KEX]);
        assert_string_equal(session->opts.wanted_methods[SSH_KEX],
                KEXALGORITHMS);
        assert_non_null(session->opts.wanted_methods[SSH_HOSTKEYS]);
        assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS],
                HOSTKEYALGORITHMS);
        assert_non_null(session->opts.pubkey_accepted_types);
        assert_string_equal(session->opts.pubkey_accepted_types,
                PUBKEYACCEPTEDTYPES);
        assert_non_null(session->opts.wanted_methods[SSH_MAC_S_C]);
        assert_string_equal(session->opts.wanted_methods[SSH_MAC_C_S], MACS);
        assert_non_null(session->opts.wanted_methods[SSH_MAC_S_C]);
        assert_string_equal(session->opts.wanted_methods[SSH_MAC_S_C], MACS);
    }
}

/**
 * @brief tests ssh_config_parse_file with Include directives from file
 */
static void torture_config_include_file(void **state)
{
    torture_config_include(state, LIBSSH_TESTCONFIG1, NULL);
}

/**
 * @brief tests ssh_config_parse_string with Include directives from string
 */
static void torture_config_include_string(void **state)
{
    torture_config_include(state, NULL, LIBSSH_TESTCONFIG_STRING1);
}

/**
 * @brief tests ssh_config_parse_file with recursive Include directives from file
 */
static void torture_config_include_recursive_file(void **state)
{
    _parse_config(*state, LIBSSH_TEST_RECURSIVE_INCLUDE, NULL, SSH_OK);
}

/**
 * @brief tests ssh_config_parse_string with Include directives from string
 */
static void torture_config_include_recursive_string(void **state)
{
    _parse_config(*state, NULL, LIBSSH_TEST_RECURSIVE_INCLUDE_STRING, SSH_OK);
}

/**
 * @brief tests ssh_config_parse_file with multiple Port settings.
 */
static void torture_config_double_ports_file(void **state)
{
    _parse_config(*state, LIBSSH_TESTCONFIG4, NULL, SSH_OK);
}

/**
 * @brief tests ssh_config_parse_string with multiple Port settings.
 */
static void torture_config_double_ports_string(void **state)
{
    _parse_config(*state, NULL, LIBSSH_TESTCONFIG_STRING4, SSH_OK);
}

static void torture_config_glob(void **state,
                                const char *file, const char *string)
{
#if defined(HAVE_GLOB) && defined(HAVE_GLOB_GL_FLAGS_MEMBER)
    int ret;
    char *v;
    ssh_session session = *state;

    _parse_config(session, file, string, SSH_OK);

    /* Test the variable presence */

    ret = ssh_options_get(session, SSH_OPTIONS_PROXYCOMMAND, &v);
    assert_true(ret == 0);
    assert_non_null(v);

    assert_string_equal(v, PROXYCMD);
    SSH_STRING_FREE_CHAR(v);

    ret = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &v);
    assert_true(ret == 0);
    assert_non_null(v);

    assert_string_equal(v, ID_FILE);
    SSH_STRING_FREE_CHAR(v);
#endif /* HAVE_GLOB && HAVE_GLOB_GL_FLAGS_MEMBER */
}

static void torture_config_glob_file(void **state)
{
    torture_config_glob(state, LIBSSH_TESTCONFIG5, NULL);
}

static void torture_config_glob_string(void **state)
{
    torture_config_glob(state, NULL, LIBSSH_TESTCONFIG_STRING5);
}

/**
 * @brief Verify the new options are passed from configuration
 */
static void torture_config_new(void ** state,
                               const char *file, const char *string)
{
    ssh_session session = *state;

    _parse_config(session, file, string, SSH_OK);

    assert_string_equal(session->opts.knownhosts, USER_KNOWN_HOSTS);
    assert_string_equal(session->opts.global_knownhosts, GLOBAL_KNOWN_HOSTS);
    assert_int_equal(session->opts.timeout, 30);
    assert_string_equal(session->opts.bindaddr, BIND_ADDRESS);
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
#endif /* WITH_ZLIB */
    assert_int_equal(session->opts.StrictHostKeyChecking, 0);
    assert_int_equal(session->opts.gss_delegate_creds, 1);
    assert_string_equal(session->opts.gss_server_identity, "example.com");
    assert_string_equal(session->opts.gss_client_identity, "home.sweet");
#ifdef WITH_GSSAPI
    assert_true(session->opts.gssapi_key_exchange);
    assert_string_equal(session->opts.gssapi_key_exchange_algs,
                        "gss-group14-sha256-");
#endif /* WITH_GSSAPI */

    assert_int_equal(ssh_get_log_level(), SSH_LOG_TRACE);
    assert_int_equal(session->common.log_verbosity, SSH_LOG_TRACE);
    assert_int_equal(session->opts.rsa_min_size, 2233);
}

static void torture_config_new_file(void **state)
{
    torture_config_new(state, LIBSSH_TESTCONFIG7, NULL);
}

static void torture_config_new_string(void **state)
{
    torture_config_new(state, NULL, LIBSSH_TESTCONFIG_STRING7);
}

/**
 * @brief Verify the authentication methods from configuration are effective
 */
static void torture_config_auth_methods(void **state,
                                        const char *file, const char *string)
{
    ssh_session session = *state;

    /* gradually disable all the methods based on different hosts */
    ssh_options_set(session, SSH_OPTIONS_HOST, "nogss");
    _parse_config(session, file, string, SSH_OK);
    assert_false(session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH);
    assert_true(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "nochallenge");
    _parse_config(session, file, string, SSH_OK);
    assert_false(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "nokbd");
    _parse_config(session, file, string, SSH_OK);
    assert_false(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "nopass");
    _parse_config(session, file, string, SSH_OK);
    assert_false(session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "nopubkey");
    _parse_config(session, file, string, SSH_OK);
    assert_false(session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH);

    /* no method should be left enabled */
    assert_int_equal(session->opts.flags, 0);

    /* gradually enable them again */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "gss");
    _parse_config(session, file, string, SSH_OK);
    assert_true(session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH);
    assert_false(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "challenge");
    _parse_config(session, file, string, SSH_OK);
    assert_true(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "kbd");
    _parse_config(session, file, string, SSH_OK);
    assert_true(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "pass");
    _parse_config(session, file, string, SSH_OK);
    assert_true(session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "pubkey");
    _parse_config(session, file, string, SSH_OK);
    assert_true(session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH);
}

/**
 * @brief Verify the authentication methods from configuration file
 * are effective
 */
static void torture_config_auth_methods_file(void **state)
{
    torture_config_auth_methods(state, LIBSSH_TESTCONFIG8, NULL);
}

/**
 * @brief Verify the authentication methods from configuration string
 * are effective
 */
static void torture_config_auth_methods_string(void **state)
{
    torture_config_auth_methods(state, NULL, LIBSSH_TESTCONFIG_STRING8);
}

static void torture_config_numeric_invalid(void **state, const char *file)
{
    ssh_session session = *state;
    struct invalid_numeric_case {
        const char *config;
        enum {
            INVALID_NUMERIC_PORT,
            INVALID_NUMERIC_TIMEOUT,
            INVALID_NUMERIC_RSA_SIZE,
        } kind;
    } configs[] = {
        {
            "Host test\n"
            "\tPort 2201abc\n",
            INVALID_NUMERIC_PORT,
        },
        {
            "Host test\n"
            "\tPort 70000\n",
            INVALID_NUMERIC_PORT,
        },
        {
            "Host test\n"
            "\tConnectTimeout 30abc\n",
            INVALID_NUMERIC_TIMEOUT,
        },
        {
            "Host test\n"
            "\tConnectTimeout 30x\n",
            INVALID_NUMERIC_TIMEOUT,
        },
        {
            "Host test\n"
            "\tConnectTimeout 3550w5d3h14m8s\n",
            INVALID_NUMERIC_TIMEOUT,
        },
        {
            "Host test\n"
            "\tRequiredRSASize 2233abc\n",
            INVALID_NUMERIC_RSA_SIZE,
        },
    };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(configs); i++) {
        const char *config = configs[i].config;

        torture_reset_config(session);
        session->opts.port = 2222;
        session->opts.timeout = 15;
        session->opts.rsa_min_size = 2048;
        ssh_options_set(session, SSH_OPTIONS_HOST, "test");
        if (file != NULL) {
            torture_write_file(file, config);
        }
        _parse_config(session, file, file != NULL ? NULL : config, SSH_OK);

        switch (configs[i].kind) {
        case INVALID_NUMERIC_PORT:
            assert_int_equal(session->opts.port, 2222);
            break;
        case INVALID_NUMERIC_TIMEOUT:
            assert_int_equal(session->opts.timeout, 15);
            break;
        case INVALID_NUMERIC_RSA_SIZE:
            assert_int_equal(session->opts.rsa_min_size, 2048);
            break;
        }
    }
}

static void torture_config_numeric_invalid_file(void **state)
{
    torture_config_numeric_invalid(state, LIBSSH_TESTCONFIG_NUMERIC_INVALID);
}

static void torture_config_numeric_invalid_string(void **state)
{
    torture_config_numeric_invalid(state, NULL);
}

static void torture_config_timeout_suffix(void **state, const char *file)
{
    ssh_session session = *state;
    struct timeout_case {
        const char *host;
        const char *value;
        long expected;
        bool infinite;
    } cases[] = {
        {"seconds", "30s", 30, false},
        {"seconds_upper", "30S", 30, false},
        {"minutes", "1m", 60, false},
        {"minutes_upper", "1M", 60, false},
        {"days", "30d", 30L * 24 * 60 * 60, false},
        {"days_upper", "1D", 24L * 60 * 60, false},
        {"weeks_upper", "1W", 7L * 24 * 60 * 60, false},
        {"int_max", "3550w5d3h14m7s", INT_MAX, false},
        {"repeat_s", "30s30s", 60, false},
        {"repeat_h", "1h1h", 7200, false},
        {"compound", "1h30m", 5400, false},
        {"compound_upper", "1H30M", 5400, false},
        {"none", "none", 0, true},
    };
    char config[256];
    size_t i;

    for (i = 0; i < ARRAY_SIZE(cases); i++) {
        torture_reset_config(session);
        ssh_options_set(session, SSH_OPTIONS_HOST, cases[i].host);
        snprintf(config,
                 sizeof(config),
                 "Host %s\n\tConnectTimeout %s\n",
                 cases[i].host,
                 cases[i].value);
        if (file != NULL) {
            torture_write_file(file, config);
        }
        _parse_config(session, file, file != NULL ? NULL : config, SSH_OK);
        if (cases[i].infinite) {
            assert_int_equal(session->opts.timeout,
                             (unsigned long)SSH_TIMEOUT_INFINITE);
            assert_int_equal(session->opts.timeout_usec, 0);
        } else {
            assert_int_equal(session->opts.timeout, cases[i].expected);
        }
    }
}

static void torture_config_timeout_suffix_file(void **state)
{
    torture_config_timeout_suffix(state, LIBSSH_TESTCONFIG_TIMEOUT_SUFFIX);
}

static void torture_config_timeout_suffix_string(void **state)
{
    torture_config_timeout_suffix(state, NULL);
}

static void torture_config_reset_boolean_state(ssh_session session)
{
    torture_reset_config(session);
    session->opts.StrictHostKeyChecking = SSH_STRICT_HOSTKEY_ASK;
    session->opts.gss_delegate_creds = 0;
    session->opts.flags = SSH_OPT_FLAG_PASSWORD_AUTH |
                          SSH_OPT_FLAG_PUBKEY_AUTH | SSH_OPT_FLAG_KBDINT_AUTH |
                          SSH_OPT_FLAG_GSSAPI_AUTH;
    session->opts.pubkey_auth = SSH_PUBKEY_AUTH_ALL;
    session->opts.identities_only = false;
}

static void torture_config_boolean_invalid(void **state, const char *file)
{
    ssh_session session = *state;
    struct invalid_boolean_case {
        const char *config;
        enum {
            INVALID_COMPRESSION,
            INVALID_IDENTITIES_ONLY,
            INVALID_GSSAPI_KEY_EXCHANGE,
            INVALID_GSSAPI_AUTH,
            INVALID_KBDINT_AUTH,
            INVALID_PASSWORD_AUTH,
            INVALID_PUBKEY_AUTH,
        } kind;
    } configs[] = {
        {
            "Host test\n"
            "\tCompression yesplease\n",
            INVALID_COMPRESSION,
        },
        {
            "Host test\n"
            "\tCompression true\n",
            INVALID_COMPRESSION,
        },
#ifndef WITH_ZLIB
        {
            "Host test\n"
            "\tCompression yes\n",
            INVALID_COMPRESSION,
        },
#endif /* WITH_ZLIB */
        {
            "Host test\n"
            "\tIdentitiesOnly nope\n",
            INVALID_IDENTITIES_ONLY,
        },
        {
            "Host test\n"
            "\tGSSAPIKeyExchange yesplease\n",
            INVALID_GSSAPI_KEY_EXCHANGE,
        },
        {
            "Host test\n"
            "\tGSSAPIAuthentication\n",
            INVALID_GSSAPI_AUTH,
        },
        {
            "Host test\n"
            "\tKbdInteractiveAuthentication\n",
            INVALID_KBDINT_AUTH,
        },
        {
            "Host test\n"
            "\tPasswordAuthentication\n",
            INVALID_PASSWORD_AUTH,
        },
        {
            "Host test\n"
            "\tPubkeyAuthentication\n",
            INVALID_PUBKEY_AUTH,
        },
    };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(configs); i++) {
        const char *config = configs[i].config;

        torture_config_reset_boolean_state(session);
        /* These invalid-value cases should behave as no-ops for the fields
         * exercised only by this test.
         */
        SAFE_FREE(session->opts.wanted_methods[SSH_COMP_C_S]);
        SAFE_FREE(session->opts.wanted_methods[SSH_COMP_S_C]);
        session->opts.gssapi_key_exchange = false;
        ssh_options_set(session, SSH_OPTIONS_HOST, "test");
        if (file != NULL) {
            torture_write_file(file, config);
        }
        _parse_config(session, file, file != NULL ? NULL : config, SSH_OK);

        switch (configs[i].kind) {
        case INVALID_COMPRESSION:
            assert_null(session->opts.wanted_methods[SSH_COMP_C_S]);
            assert_null(session->opts.wanted_methods[SSH_COMP_S_C]);
            break;
        case INVALID_IDENTITIES_ONLY:
            assert_false(session->opts.identities_only);
            break;
        case INVALID_GSSAPI_KEY_EXCHANGE:
            assert_false(session->opts.gssapi_key_exchange);
            break;
        case INVALID_GSSAPI_AUTH:
            assert_true(session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH);
            break;
        case INVALID_KBDINT_AUTH:
            assert_true(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);
            break;
        case INVALID_PASSWORD_AUTH:
            assert_true(session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH);
            break;
        case INVALID_PUBKEY_AUTH:
            assert_true(session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH);
            assert_int_equal(session->opts.pubkey_auth, SSH_PUBKEY_AUTH_ALL);
            break;
        }
    }
}

static void torture_config_boolean_invalid_file(void **state)
{
    torture_config_boolean_invalid(state, LIBSSH_TESTCONFIG_BOOLEAN_INVALID);
}

static void torture_config_boolean_invalid_string(void **state)
{
    torture_config_boolean_invalid(state, NULL);
}

static void torture_config_boolean_compat(void **state, const char *file)
{
    ssh_session session = *state;
    char config[256];
    size_t i;
    struct strict_hostkey_case {
        const char *value;
        int expected;
    } strict_cases[] = {
        {"true", SSH_STRICT_HOSTKEY_YES},
        {"false", SSH_STRICT_HOSTKEY_OFF},
        {"ask", SSH_STRICT_HOSTKEY_ASK},
        {"accept-new", SSH_STRICT_HOSTKEY_ACCEPT_NEW},
        {"off", SSH_STRICT_HOSTKEY_OFF},
    };
    struct pubkey_auth_case {
        const char *value;
        int expected;
        bool enabled;
    } pubkey_cases[] = {
        {"true", SSH_PUBKEY_AUTH_ALL, true},
        {"false", SSH_PUBKEY_AUTH_NO, false},
        {"unbound", SSH_PUBKEY_AUTH_UNBOUND, true},
        {"host-bound", SSH_PUBKEY_AUTH_HOST_BOUND, true},
    };
    struct gssapi_key_exchange_case {
        const char *value;
        bool expected;
    } gssapi_key_exchange_cases[] = {
        {"true", true},
        {"false", false},
    };

    for (i = 0; i < ARRAY_SIZE(strict_cases); i++) {
        torture_config_reset_boolean_state(session);
        ssh_options_set(session, SSH_OPTIONS_HOST, "test");
        snprintf(config,
                 sizeof(config),
                 "Host test\n\tStrictHostKeyChecking %s\n",
                 strict_cases[i].value);
        if (file != NULL) {
            torture_write_file(file, config);
        }
        _parse_config(session, file, file != NULL ? NULL : config, SSH_OK);
        assert_int_equal(session->opts.StrictHostKeyChecking,
                         strict_cases[i].expected);
    }

    for (i = 0; i < ARRAY_SIZE(pubkey_cases); i++) {
        torture_config_reset_boolean_state(session);
        ssh_options_set(session, SSH_OPTIONS_HOST, "test");
        snprintf(config,
                 sizeof(config),
                 "Host test\n\tPubkeyAuthentication %s\n",
                 pubkey_cases[i].value);
        if (file != NULL) {
            torture_write_file(file, config);
        }
        _parse_config(session, file, file != NULL ? NULL : config, SSH_OK);
        assert_int_equal(session->opts.pubkey_auth, pubkey_cases[i].expected);
        assert_int_equal((session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH) != 0,
                         pubkey_cases[i].enabled);
    }

    for (i = 0; i < ARRAY_SIZE(gssapi_key_exchange_cases); i++) {
        torture_config_reset_boolean_state(session);
        session->opts.gssapi_key_exchange =
            !gssapi_key_exchange_cases[i].expected;
        ssh_options_set(session, SSH_OPTIONS_HOST, "test");
        snprintf(config,
                 sizeof(config),
                 "Host test\n\tGSSAPIKeyExchange %s\n",
                 gssapi_key_exchange_cases[i].value);
        if (file != NULL) {
            torture_write_file(file, config);
        }
        _parse_config(session, file, file != NULL ? NULL : config, SSH_OK);
#ifdef WITH_GSSAPI
        assert_int_equal(session->opts.gssapi_key_exchange,
                         gssapi_key_exchange_cases[i].expected);
#else
        assert_int_equal(session->opts.gssapi_key_exchange,
                         !gssapi_key_exchange_cases[i].expected);
#endif
    }

    torture_config_reset_boolean_state(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "test");
    snprintf(config,
             sizeof(config),
             "Host test\n"
             "\tPasswordAuthentication true\n"
             "\tKbdInteractiveAuthentication false\n"
             "\tGSSAPIAuthentication true\n"
             "\tGSSAPIDelegateCredentials true\n"
             "\tIdentitiesOnly false\n");
    if (file != NULL) {
        torture_write_file(file, config);
    }
    _parse_config(session, file, file != NULL ? NULL : config, SSH_OK);
    assert_true(session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH);
    assert_false(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);
    assert_true(session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH);
    assert_int_equal(session->opts.gss_delegate_creds, 1);
    assert_false(session->opts.identities_only);
}

static void torture_config_boolean_compat_file(void **state)
{
    torture_config_boolean_compat(state, LIBSSH_TESTCONFIG_BOOLEAN_COMPAT);
}

static void torture_config_boolean_compat_string(void **state)
{
    torture_config_boolean_compat(state, NULL);
}

/**
 * @brief Helper for checking hostname, username and port of ssh_jump_info_struct
 */
static void
helper_proxy_jump_check(struct ssh_iterator *jump,
                        const char *hostname,
                        const char *username,
                        const char *port)
{
    struct ssh_jump_info_struct *jis =
        ssh_iterator_value(struct ssh_jump_info_struct *, jump);

    assert_string_equal(jis->hostname, hostname);

    if (username != NULL) {
        assert_string_equal(jis->username, username);
    } else {
        assert_null(jis->username);
    }

    if (port != NULL) {
        int iport = strtol(port, NULL, 10);
        assert_int_equal(jis->port, iport);
    } else {
        /* No port in the ProxyJump spec: left unset for the jump host's own
         * configuration to supply. */
        assert_int_equal(jis->port, 0);
    }
}

/**
 * @brief Verify the configuration parser does not choke on unknown
 * or unsupported configuration options
 */
static void torture_config_unknown(void **state,
                                   const char *file, const char *string)
{
    ssh_session session = *state;
    int ret = 0;

    /* test corner cases */
    /* Without libssh proxy jump */
    torture_setenv("OPENSSH_PROXYJUMP", "1");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -W '[%h]:%p' many-spaces.com");
    assert_string_equal(session->opts.host, "equal.sign");

    ret = ssh_config_parse_file(session, "/etc/ssh/ssh_config");
    assert_true(ret == 0);
    ret = ssh_config_parse_file(session, GLOBAL_CLIENT_CONFIG);
    assert_true(ret == 0);
    torture_unsetenv("OPENSSH_PROXYJUMP");
}

/**
 * @brief Verify the configuration parser does not choke on unknown
 * or unsupported configuration options in configuration file
 */
static void torture_config_unknown_file(void **state)
{
    torture_config_unknown(state, LIBSSH_TESTCONFIG9, NULL);
}

/**
 * @brief Verify the configuration parser does not choke on unknown
 * or unsupported configuration options in configuration string
 */
static void torture_config_unknown_string(void **state)
{
    torture_config_unknown(state, NULL, LIBSSH_TESTCONFIG_STRING9);
}

/**
 * @brief Verify the configuration parser accepts Match keyword with
 * full OpenSSH syntax.
 */
static void torture_config_match(void **state,
                                 const char *file, const char *string)
{
    ssh_session session = *state;
    char *localuser = NULL;
    const char *config = NULL;
    char config_string[1024];

    /* Without any settings we should get all-matched.com hostname */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "unmatched");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "all-matched.com");
    assert_string_equal(session->opts.originalhost, "unmatched");

    /* Hostname example does simple hostname matching */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "example.com");
    assert_string_equal(session->opts.originalhost, "example");

    /* We can match also both hosts from a comma separated list */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example1");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "exampleN");
    assert_string_equal(session->opts.originalhost, "example1");

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example2");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "exampleN");
    assert_string_equal(session->opts.originalhost, "example2");

    /* We can match by originalhost */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "example.com");
    assert_string_equal(session->opts.originalhost, "example");
    /* Match originalhost sets User */
    assert_string_equal(session->opts.username, "originaluser");

    /* We can match by user - clear originalhost to isolate user match */
    torture_reset_config(session);
    SAFE_FREE(session->opts.originalhost);
    ssh_options_set(session, SSH_OPTIONS_USER, "guest");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "guest.com");

    /* We can combine two options on a single line to match both of them */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_USER, "tester");
    ssh_options_set(session, SSH_OPTIONS_HOST, "testhost");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "testhost.com");
    assert_string_equal(session->opts.originalhost, "testhost");

    /* We can also negate conditions */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_USER, "not-tester");
    ssh_options_set(session, SSH_OPTIONS_HOST, "testhost");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "nonuser-testhost.com");
    assert_string_equal(session->opts.originalhost, "testhost");

    /* In this part, we try various other config files and strings. */

    /* Match host compares against resolved hostname */
    config = "Host ssh-host\n"
             "\tHostname 10.1.1.1\n"
             "Match host 10.1.1.*\n"
             "\tPort 2222\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    session->opts.port = 0;
    ssh_options_set(session, SSH_OPTIONS_HOST, "ssh-host");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "10.1.1.1");
    assert_string_equal(session->opts.originalhost, "ssh-host");
    assert_int_equal(session->opts.port, 2222);

    /* Match host falls back to originalhost when host is NULL */
    config = "Match host my_alias\n"
             "\tHostName alias-matched.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    SAFE_FREE(session->opts.username);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my_alias");
    assert_null(session->opts.host);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "alias-matched.com");

    /* Match final is not completely supported, but should do quite much the
     * same as "match all". The trailing "all" is not mandatory. */
    config = "Match final all\n"
             "\tHostName final-all.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "final-all.com");

    config = "Match final\n"
             "\tHostName final.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "final.com");

    /* Match canonical is not completely supported, but should do quite
     * much the same as "match all". The trailing "all" is not mandatory. */
    config = "Match canonical all\n"
             "\tHostName canonical-all.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "canonical-all.com");

    config = "Match canonical all\n"
             "\tHostName canonical.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "canonical.com");

    localuser = ssh_get_local_username();
    assert_non_null(localuser);
    snprintf(config_string, sizeof(config_string),
             "Match localuser %s\n"
             "\tHostName otherhost\n",
             localuser);
    config = config_string;
    free(localuser);
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "otherhost");

    config = "Match version libssh_*\n"
             "\tHostName versioned-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "versioned-host.com");

    config = "Match !version definitely-not-the-current-libssh-version\n"
             "\tHostName negated-versioned-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "negated-versioned-host.com");

    config = "Tag tag_name\n"
             "Match tagged tag*\n"
             "\tHostName tagged-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "tagged-host.com");
    assert_string_equal(session->opts.tag, "tag_name");

    config = "Tag tag_name\n"
             "Match tagged=tag*\n"
             "\tHostName tagged-inline-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "tagged-inline-host.com");
    assert_string_equal(session->opts.tag, "tag_name");

    config = "Tag \"tag name\"\n"
             "Match tagged=\"tag name\"\n"
             "\tHostName quoted-tagged-inline-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "quoted-tagged-inline-host.com");
    assert_string_equal(session->opts.tag, "tag name");

    config = "Tag \"tag name\"\n"
             "Match tagged=tag\\ name\n"
             "\tHostName escaped-tagged-inline-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "escaped-tagged-inline-host.com");
    assert_string_equal(session->opts.tag, "tag name");

    config = "Tag config-tag\n"
             "Match tagged config*\n"
             "\tHostName overridden-tagged-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    session->opts.tag = strdup("preset-tag");
    assert_non_null(session->opts.tag);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "overridden-tagged-host.com");
    assert_string_equal(session->opts.tag, "config-tag");

    config = "Tag first\n"
             "Tag second\n"
             "Match tagged first\n"
             "\tHostName tagged-first-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "tagged-first-host.com");
    assert_string_equal(session->opts.tag, "first");

    config = "Match exec true\n"
             "\tHostName execed-true.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "otherhost");
    _parse_config(session, file, string, SSH_OK);
#ifndef WITH_EXEC
    /* The match exec is not supported on windows at this moment */
    assert_string_equal(session->opts.host, "otherhost");
#else
    assert_string_equal(session->opts.host, "execed-true.com");
#endif

    config = "Match !exec false\n"
             "\tHostName execed-false.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "otherhost");
    _parse_config(session, file, string, SSH_OK);
#ifndef WITH_EXEC
    /* The match exec is not supported on windows at this moment */
    assert_string_equal(session->opts.host, "otherhost");
#else
    assert_string_equal(session->opts.host, "execed-false.com");
#endif

    config = "Match exec \"test 1 -eq 1\"\n"
             "\tHostName execed-arguments.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "otherhost");
    _parse_config(session, file, string, SSH_OK);
#ifndef WITH_EXEC
    /* The match exec is not supported on windows at this moment */
    assert_string_equal(session->opts.host, "otherhost");
#else
    assert_string_equal(session->opts.host, "execed-arguments.com");
#endif

    config = "Match exec \"test %n = my-alias\"\n"
             "\tHostName execed-originalhost.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my-alias");
    _parse_config(session, file, string, SSH_OK);
#ifndef WITH_EXEC
    /* The match exec is not supported on windows at this moment */
    assert_string_equal(session->opts.host, "my-alias");
#else
    assert_string_equal(session->opts.host, "execed-originalhost.com");
#endif
    assert_string_equal(session->opts.originalhost, "my-alias");

    /* Try to create some invalid configurations */
    /* Missing argument to Match*/
    config = "Match\n"
             "\tHost missing.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "unmatched");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "unmatched");

    /* Missing argument to option originalhost */
    config = "Match originalhost\n"
             "\tHost originalhost.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing argument to option localuser */
    config = "Match localuser\n"
             "\tUser localuser2\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing argument to option user */
    config = "Match user\n"
             "\tUser user2\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing argument to option host */
    config = "Match host\n"
             "\tUser host2\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing argument to option version */
    config = "Match version\n"
             "\tUser version2\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing argument to option tagged */
    config = "Match tagged\n"
             "\tUser tagged2\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing argument to Tag */
    config = "Tag\n"
             "\tUser tagged2\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing argument to option exec */
    config = "Match exec\n"
             "\tUser exec\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_ERROR);

    /* Match tagged does not apply when no Tag was set */
    config = "Match tagged tag_name\n"
             "\tHostName never-matched.com\n"
             "Match all\n"
             "\tHostName config-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example.com");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "config-host.com");

    /* An empty Match tagged= matches an unset tag */
    config = "Match tagged=\n"
             "\tHostName empty-tag-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example.com");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "empty-tag-host.com");

    /* An empty Match tagged "" matches an unset tag */
    config = "Match tagged \"\"\n"
             "\tHostName empty-separated-tag-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example.com");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "empty-separated-tag-host.com");

    /* An empty Match tagged= does not match after a Tag was set */
    config = "Tag tag_name\n"
             "Match tagged=\n"
             "\tHostName never-matched.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example.com");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "example.com");

    /* An empty Match tagged "" does not match after a Tag was set */
    config = "Tag tag_name\n"
             "Match tagged \"\"\n"
             "\tHostName never-matched.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example.com");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "example.com");

    /* Unterminated quotes in Match tagged= are rejected */
    config = "Tag \"tag name\"\n"
             "Match tagged=\"unterminated\n"
             "\tHostName invalid-tag-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing argument to Match keyword */
    config = "Match\n"
             "\tHostName never-matched.com\n"
             "Match all\n"
             "\tHostName config-host.com\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example.com");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.host, "config-host.com");
}

/**
 * @brief Verify the configuration parser accepts Match keyword with
 * full OpenSSH syntax through configuration file.
 */
static void torture_config_match_file(void **state)
{
    torture_config_match(state, LIBSSH_TESTCONFIG10, NULL);
}

/**
 * @brief Verify the configuration parser accepts Match keyword with
 * full OpenSSH syntax through configuration string.
 */
static void torture_config_match_string(void **state)
{
    torture_config_match(state, NULL, LIBSSH_TESTCONFIG_STRING10);
}

static void torture_config_match_version_negative(void **state)
{
    ssh_session session = *state;
    char config[1024];

    config[0] = '\0';
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "unmatched");
    snprintf(config,
             sizeof(config),
             "Match version definitely-not-the-current-libssh-version\n"
             "\tHostName unmatched-version-host.com\n"
             "Match all\n"
             "\tHostName nonmatching-version-fallback.com\n");
    _parse_config(session, NULL, config, SSH_OK);
    assert_string_equal(session->opts.host, "nonmatching-version-fallback.com");

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "unmatched");
    snprintf(config,
             sizeof(config),
             "Match !version libssh_*\n"
             "\tHostName not-applied-negated-version-host.com\n"
             "Match all\n"
             "\tHostName negated-version-fallback.com\n");
    _parse_config(session, NULL, config, SSH_OK);
    assert_string_equal(session->opts.host, "negated-version-fallback.com");
}

/**
 * @brief Verify we can parse ProxyJump configuration option
 */
static void torture_config_proxyjump(void **state,
                                     const char *file, const char *string)
{
    ssh_session session = *state;

    const char *config = NULL;


    /* Tests for libssh based proxyjump */
    /* Simplest version with just a hostname */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "simple");
    _parse_config(session, file, string, SSH_OK);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "jumpbox",
                            NULL,
                            NULL);

    /* With username */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "user");
    _parse_config(session, file, string, SSH_OK);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "jumpbox",
                            "user",
                            NULL);

    /* With port */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "port");
    _parse_config(session, file, string, SSH_OK);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "jumpbox",
                            NULL,
                            "2222");

    /* Two step jump */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "two-step");
    _parse_config(session, file, string, SSH_OK);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "second",
                            "u2",
                            "33");
    helper_proxy_jump_check(session->opts.proxy_jumps->root->next,
                            "first",
                            "u1",
                            "222");

    /* Three step jump */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "three-step");
    _parse_config(session, file, string, SSH_OK);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "third",
                            "u3",
                            "444");
    helper_proxy_jump_check(session->opts.proxy_jumps->root->next,
                            "second",
                            "u2",
                            "33");
    helper_proxy_jump_check(session->opts.proxy_jumps->root->next->next,
                            "first",
                            "u1",
                            "222");

    /* none */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "none");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(ssh_list_count(session->opts.proxy_jumps), 0);

    /* If also ProxyCommand is specified, the first is applied */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "only-command");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand, PROXYCMD);
    assert_int_equal(ssh_list_count(session->opts.proxy_jumps), 0);

    /* If also ProxyCommand is specified, the first is applied */
    torture_reset_config(session);
    SAFE_FREE(session->opts.ProxyCommand);
    ssh_options_set(session, SSH_OPTIONS_HOST, "only-jump");
    _parse_config(session, file, string, SSH_OK);
    assert_null(session->opts.ProxyCommand);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "jumpbox",
                            NULL,
                            NULL);

    /* IPv6 address */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "ipv6");
    _parse_config(session, file, string, SSH_OK);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "2620:52:0::fed",
                            NULL,
                            NULL);

    torture_reset_config(session);

    /* Tests for proxycommand based proxyjump */
    torture_setenv("OPENSSH_PROXYJUMP", "1");

    /* Simplest version with just a hostname */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "simple");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand, "ssh -W '[%h]:%p' jumpbox");

    /* With username */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "user");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -l user -W '[%h]:%p' jumpbox");

    /* With port */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "port");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -p 2222 -W '[%h]:%p' jumpbox");

    /* Two step jump */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "two-step");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -l u1 -p 222 -J u2@second:33 -W '[%h]:%p' first");

    /* Three step jump */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "three-step");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -l u1 -p 222 -J u2@second:33,u3@third:444 -W '[%h]:%p' first");

    /* none */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "none");
    _parse_config(session, file, string, SSH_OK);
    assert_true(session->opts.ProxyCommand == NULL);

    /* If also ProxyCommand is specified, the first is applied */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "only-command");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand, PROXYCMD);

    /* If also ProxyCommand is specified, the first is applied */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "only-jump");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -W '[%h]:%p' jumpbox");

    /* IPv6 address */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "ipv6");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -W '[%h]:%p' 2620:52:0::fed");

    /* Multiple @ is allowed in second jump */
    config = "Host allowed-hostname\n"
             "\tProxyJump localhost,user@principal.com@jumpbox:22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "allowed-hostname");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -J user@principal.com@jumpbox:22 -W '[%h]:%p' localhost");

    /* Multiple @ is allowed */
    config = "Host allowed-hostname\n"
             "\tProxyJump user@principal.com@jumpbox:22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "allowed-hostname");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -l user@principal.com -p 22 -W '[%h]:%p' jumpbox");
    torture_unsetenv("OPENSSH_PROXYJUMP");

    /* Tests for libssh based proxyjump */
    /* Multiple @ is allowed in second jump */
    config = "Host allowed-hostname\n"
             "\tProxyJump localhost,user@principal.com@jumpbox:22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "allowed-hostname");
    _parse_config(session, file, string, SSH_OK);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "jumpbox",
                            "user@principal.com",
                            "22");

    /* Multiple @ is allowed */
    config = "Host allowed-hostname\n"
             "\tProxyJump user@principal.com@jumpbox:22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "allowed-hostname");
    _parse_config(session, file, string, SSH_OK);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "jumpbox",
                            "user@principal.com",
                            "22");
    /* Non-RFC-1035 alias (underscore) — accepted with non-strict parse */
    config = "Host alias-jump\n"
             "\tProxyJump my_alias\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "alias-jump");
    _parse_config(session, file, string, SSH_OK);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "my_alias",
                            NULL,
                            NULL);

    /* Non-RFC-1035 alias in multi-hop second jump */
    config = "Host alias-multi\n"
             "\tProxyJump localhost,my_alias:2222\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "alias-multi");
    _parse_config(session, file, string, SSH_OK);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "my_alias",
                            NULL,
                            "2222");
    helper_proxy_jump_check(session->opts.proxy_jumps->root->next,
                            "localhost",
                            NULL,
                            NULL);

    /* Non-RFC-1035 alias — proxycommand based */
    torture_setenv("OPENSSH_PROXYJUMP", "1");

    config = "Host alias-jump\n"
             "\tProxyJump my_alias\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "alias-jump");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -W '[%h]:%p' my_alias");

    /* Non-RFC-1035 alias in multi-hop — proxycommand based */
    config = "Host alias-multi\n"
             "\tProxyJump localhost,my_alias:2222\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "alias-multi");
    _parse_config(session, file, string, SSH_OK);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -J my_alias:2222 -W '[%h]:%p' localhost");

    torture_unsetenv("OPENSSH_PROXYJUMP");

    /* In this part, we try various other config files and strings. */
    torture_setenv("OPENSSH_PROXYJUMP", "1");

    /* Try to create some invalid configurations */
    /* Non-numeric port */
    config = "Host bad-port\n"
             "\tProxyJump jumpbox:22bad22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "bad-port");
    _parse_config(session, file, string, SSH_ERROR);

    /* Braces mismatch in hostname */
    config = "Host mismatch\n"
             "\tProxyJump [::1\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "mismatch");
    _parse_config(session, file, string, SSH_ERROR);

    /* Bad host-port separator */
    config = "Host beef\n"
             "\tProxyJump [dead::beef]::22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "beef");
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing hostname */
    config = "Host no-host\n"
             "\tProxyJump user@:22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-host");
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing user */
    config = "Host no-user\n"
             "\tProxyJump @host:22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-user");
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing port */
    config = "Host no-port\n"
             "\tProxyJump host:\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-port");
    _parse_config(session, file, string, SSH_ERROR);

    /* Non-numeric port in second jump */
    config = "Host bad-port-2\n"
             "\tProxyJump localhost,jumpbox:22bad22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "bad-port-2");
    _parse_config(session, file, string, SSH_ERROR);

    /* Braces mismatch in second jump */
    config = "Host mismatch\n"
             "\tProxyJump localhost,[::1:20\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "mismatch");
    _parse_config(session, file, string, SSH_ERROR);

    /* Bad host-port separator in second jump */
    config = "Host beef\n"
             "\tProxyJump localhost,[dead::beef]::22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "beef");
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing hostname in second jump */
    config = "Host no-host\n"
             "\tProxyJump localhost,user@:22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-host");
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing user in second jump */
    config = "Host no-user\n"
             "\tProxyJump localhost,@host:22\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-user");
    _parse_config(session, file, string, SSH_ERROR);

    /* Missing port in second jump */
    config = "Host no-port\n"
             "\tProxyJump localhost,host:\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-port");
    _parse_config(session, file, string, SSH_ERROR);

    torture_unsetenv("OPENSSH_PROXYJUMP");
}

/**
 * @brief Verify we can parse ProxyJump configuration option from file
 */
static void torture_config_proxyjump_file(void **state)
{
    torture_config_proxyjump(state, LIBSSH_TESTCONFIG11, NULL);
}

/**
 * @brief Verify we can parse ProxyJump configuration option from string
 */
static void torture_config_proxyjump_string(void **state)
{
    torture_config_proxyjump(state, NULL, LIBSSH_TESTCONFIG_STRING11);
}

/**
 * @brief Verify we can parse ControlPath configuration option
 */
static void torture_config_control_path(void **state,
                                        const char *file, const char *string)
{
    ssh_session session = *state;

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "simple");
    _parse_config(session, file, string, SSH_OK);
    assert_null(session->opts.control_path);

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "none");
    _parse_config(session, file, string, SSH_OK);
    assert_null(session->opts.control_path);
}

/**
 * @brief Verify we can parse ControlPath configuration option from string
 */
static void torture_config_control_path_string(void **state)
{
    torture_config_control_path(state, NULL, LIBSSH_TESTCONFIG_STRING17);
}

/**
 * @brief Verify we can parse ControlPath configuration option from file
 */
static void torture_config_control_path_file(void **state)
{
    torture_config_control_path(state, LIBSSH_TESTCONFIG17, NULL);
}

/**
 * @brief Verify we can parse ControlMaster configuration option
 */
static void torture_config_control_master(void **state,
                                          const char *file, const char *string)
{
    ssh_session session = *state;

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "simple");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.control_master, SSH_CONTROL_MASTER_NO);

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "none");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.control_master, SSH_CONTROL_MASTER_NO);
}

/**
 * @brief Verify we can parse ControlMaster configuration option from string
 */
static void torture_config_control_master_string(void **state)
{
    torture_config_control_master(state, NULL, LIBSSH_TESTCONFIG_STRING17);
}

/**
 * @brief Verify we can parse ControlMaster configuration option from file
 */
static void torture_config_control_master_file(void **state)
{
    torture_config_control_master(state, LIBSSH_TESTCONFIG17, NULL);
}

/**
 * @brief Verify we can parse BatchMode configuration option
 */
static void torture_config_batch_mode(void **state,
                                      const char *file,
                                      const char *string)
{
    ssh_session session = *state;

    int batch_mode = -1;
    int rc;

    /* BatchMode no: batch_mode should be 0 */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "nobatch");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_BATCH_MODE, &batch_mode);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(batch_mode, 0);

    /* BatchMode yes: batch_mode should be 1 */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "batch");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_BATCH_MODE, &batch_mode);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(batch_mode, 1);
}

/**
 * @brief Verify we can parse BatchMode configuration option from string
 */
static void torture_config_batch_mode_string(void **state)
{
    torture_config_batch_mode(state, NULL, LIBSSH_TESTCONFIG_STRING19);
}

/**
 * @brief Verify we can parse PreferredAuthentications config option
 */
static void torture_config_preferred_authentications(void **state,
                                                     const char *file,
                                                     const char *string)
{
    ssh_session session = *state;
    char *value = NULL;
    int rc;

    /* Host without PreferredAuthentications then option should be NULL */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "nopref");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get(session,
                         SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                         &value);
    assert_int_equal(rc, SSH_ERROR);
    assert_null(value);

    /* Host that has PreferredAuthentications set */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "withpref");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get(session,
                         SSH_OPTIONS_PREFERRED_AUTHENTICATIONS,
                         &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "publickey,password");
    ssh_string_free_char(value);
    value = NULL;
}

static void torture_config_preferred_authentications_string(void **state)
{
    torture_config_preferred_authentications(state,
                                             NULL,
                                             LIBSSH_TESTCONFIG_STRING20);
}

static void torture_config_preferred_authentications_file(void **state)
{
    torture_config_preferred_authentications(state,
                                             LIBSSH_TESTCONFIG20,
                                             NULL);
}

/**
 * @brief Verify we can parse BatchMode configuration option from file
 */
static void torture_config_batch_mode_file(void **state)
{
    torture_config_batch_mode(state, LIBSSH_TESTCONFIG19, NULL);
}

/**
 * @brief Verify we can parse ExitOnForwardFailure configuration option
 */
static void torture_config_exit_on_forward_failure(void **state,
                                                   const char *file,
                                                   const char *string)
{
    ssh_session session = *state;

    int exit_on_forward_failure = -1;
    int rc = SSH_OK;

    /* ExitOnForwardFailure no: exit_on_forward_failure should be 0 */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "exit_fwd_no");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_EXIT_ON_FORWARD_FAILURE, &exit_on_forward_failure);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(exit_on_forward_failure, 0);

    /* ExitOnForwardFailure yes: exit_on_forward_failure should be 1 */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "exit_fwd_yes");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_EXIT_ON_FORWARD_FAILURE, &exit_on_forward_failure);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(exit_on_forward_failure, 1);
}

/**
 * @brief Verify we can parse ExitOnForwardFailure configuration option from string
 */
static void torture_config_exit_on_forward_failure_string(void **state)
{
    torture_config_exit_on_forward_failure(state, NULL, LIBSSH_TESTCONFIG_STRING29);
}

/**
 * @brief Verify we can parse ExitOnForwardFailure configuration option from file
 */
static void torture_config_exit_on_forward_failure_file(void **state)
{
    torture_config_exit_on_forward_failure(state, LIBSSH_TESTCONFIG29, NULL);
}

/**
 * @brief Verify we can parse ServerAliveInterval configuration option
 */
static void torture_config_server_alive_interval(void **state,
                                                 const char *file,
                                                 const char *string)
{
    ssh_session session = *state;

    int interval = -1;
    int rc;

    /* Host with ServerAliveInterval 10: interval should be 10 */
    torture_reset_config(session);
    session->opts.server_alive_interval = 0;
    ssh_options_set(session, SSH_OPTIONS_HOST, "shortinterval");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session,
                             SSH_OPTIONS_SERVER_ALIVE_INTERVAL,
                             &interval);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(interval, 10);

    /* Host with ServerAliveInterval 300: interval should be 300 */
    torture_reset_config(session);
    session->opts.server_alive_interval = 0;
    ssh_options_set(session, SSH_OPTIONS_HOST, "longinterval");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session,
                             SSH_OPTIONS_SERVER_ALIVE_INTERVAL,
                             &interval);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(interval, 300);

    /* Host without ServerAliveInterval: interval should remain 0 */
    torture_reset_config(session);
    session->opts.server_alive_interval = 0;
    ssh_options_set(session, SSH_OPTIONS_HOST, "defaultinterval");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session,
                             SSH_OPTIONS_SERVER_ALIVE_INTERVAL,
                             &interval);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(interval, 0);
}

/**
 * @brief Verify we can parse ServerAliveInterval from string
 */
static void torture_config_server_alive_interval_string(void **state)
{
    torture_config_server_alive_interval(state,
                                         NULL,
                                         LIBSSH_TESTCONFIG_STRING30);
}

/**
 * @brief Verify we can parse ServerAliveInterval from file
 */
static void torture_config_server_alive_interval_file(void **state)
{
    torture_config_server_alive_interval(state,
                                         LIBSSH_TESTCONFIG30,
                                         NULL);
}

/**
 * @brief Verify we can parse ServerAliveCountMax configuration option
 */
static void torture_config_server_alive_count_max(void **state,
                                                   const char *file,
                                                   const char *string)
{
    ssh_session session = *state;

    int count_max = -1;
    int rc;

    /* Host with ServerAliveCountMax 1: count_max should be 1 */
    torture_reset_config(session);
    session->opts.server_alive_count_max = 0;
    ssh_options_set(session, SSH_OPTIONS_HOST, "lowcount");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session,
                             SSH_OPTIONS_SERVER_ALIVE_COUNT_MAX,
                             &count_max);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(count_max, 1);

    /* Host with ServerAliveCountMax 10: count_max should be 10 */
    torture_reset_config(session);
    session->opts.server_alive_count_max = 0;
    ssh_options_set(session, SSH_OPTIONS_HOST, "highcount");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session,
                             SSH_OPTIONS_SERVER_ALIVE_COUNT_MAX,
                             &count_max);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(count_max, 10);

    /* Host without ServerAliveCountMax: count_max should remain 0 */
    torture_reset_config(session);
    session->opts.server_alive_count_max = 0;
    ssh_options_set(session, SSH_OPTIONS_HOST, "defaultcount");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session,
                             SSH_OPTIONS_SERVER_ALIVE_COUNT_MAX,
                             &count_max);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(count_max, 0);
}

/**
 * @brief Verify we can parse ServerAliveCountMax from string
 */
static void torture_config_server_alive_count_max_string(void **state)
{
    torture_config_server_alive_count_max(state,
                                          NULL,
                                          LIBSSH_TESTCONFIG_STRING31);
}

/**
 * @brief Verify we can parse ServerAliveCountMax from file
 */
static void torture_config_server_alive_count_max_file(void **state)
{
    torture_config_server_alive_count_max(state,
                                          LIBSSH_TESTCONFIG31,
                                          NULL);
}

/**
 * @brief Verify we can parse ForwardAgent configuration option
 */
static void torture_config_forward_agent(void **state,
                                         const char *file,
                                         const char *string)
{
    ssh_session session = *state;

    int forward_agent = -1;
    char *sock_path = NULL;
    int rc = SSH_OK;

    /* ForwardAgent no: forward_agent should be 0 */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "fwd_no");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_FORWARD_AGENT, &forward_agent);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(forward_agent, 0);

    /* ForwardAgent yes: forward_agent should be 1 */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "fwd_yes");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_FORWARD_AGENT, &forward_agent);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(forward_agent, 1);

    /* ForwardAgent /tmp/agent.sock: forwarding enabled and socket path stored */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "fwd_sock");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_FORWARD_AGENT, &forward_agent);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(forward_agent, 1);
    rc = ssh_options_get(session, SSH_OPTIONS_FORWARD_AGENT_SOCK_PATH, &sock_path);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(sock_path, "/tmp/agent.sock");
    ssh_string_free_char(sock_path);
    sock_path = NULL;

    /* ForwardAgent $SSH_AUTH_SOCK: enabled and the literal $VAR stored */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "fwd_env");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_FORWARD_AGENT, &forward_agent);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(forward_agent, 1);
    rc = ssh_options_get(session, SSH_OPTIONS_FORWARD_AGENT_SOCK_PATH, &sock_path);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(sock_path, "$SSH_AUTH_SOCK");
    ssh_string_free_char(sock_path);
    sock_path = NULL;

    /* ForwardAgent true: forward_agent should be 1 */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "fwd_true");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_FORWARD_AGENT, &forward_agent);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(forward_agent, 1);

    /* ForwardAgent false: forward_agent should be 0 */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "fwd_false");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_FORWARD_AGENT, &forward_agent);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(forward_agent, 0);
}

/**
 * @brief Verify we can parse ForwardAgent configuration option from string
 */
static void torture_config_forward_agent_string(void **state)
{
    torture_config_forward_agent(state, NULL, LIBSSH_TESTCONFIG_STRING32);
}

/**
 * @brief Verify we can parse ForwardAgent configuration option from file
 */
static void torture_config_forward_agent_file(void **state)
{
    torture_config_forward_agent(state, LIBSSH_TESTCONFIG32, NULL);
}

/**
 * @brief Verify we can parse NumberOfPasswordPrompts configuration option
 */
static void torture_config_number_of_password_prompts(void **state,
                                                      const char *file,
                                                      const char *string)
{
    ssh_session session = *state;
    int result = -1;
    int rc = 0;

    /* Host with NumberOfPasswordPrompts set */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "fewprompts");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session,
                             SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS,
                             &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 1);

    /* Host without the directive it should remain 0*/
    memset(&session->opts.number_of_password_prompts, 0,
           sizeof(session->opts.number_of_password_prompts));
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "defaultprompts");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session,
                             SSH_OPTIONS_NUMBER_OF_PASSWORD_PROMPTS,
                             &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 0);
}

static void torture_config_number_of_password_prompts_string(void **state)
{
    torture_config_number_of_password_prompts(state,
                                              NULL,
                                              LIBSSH_TESTCONFIG_STRING21);
}

static void torture_config_number_of_password_prompts_file(void **state)
{
    torture_config_number_of_password_prompts(state,
                                              LIBSSH_TESTCONFIG21,
                                              NULL);
}

/**
* @brief Verify we can parse RequestTTY configuration option
 */
static void torture_config_request_tty(void **state,
                                       const char *file,
                                       const char *string)
{
    ssh_session session = *state;
    int request_tty = -1;
    int rc = 0;

    /* RequestTTY no: request_tty should be SSH_REQUEST_TTY_NO */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "notty");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_REQUEST_TTY, &request_tty);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(request_tty, SSH_REQUEST_TTY_NO);

    /* RequestTTY yes: request_tty should be SSH_REQUEST_TTY_YES */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "ttyyes");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_REQUEST_TTY, &request_tty);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(request_tty, SSH_REQUEST_TTY_YES);

    /* RequestTTY auto: request_tty should be SSH_REQUEST_TTY_AUTO */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "ttyauto");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_REQUEST_TTY, &request_tty);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(request_tty, SSH_REQUEST_TTY_AUTO);

    /* RequestTTY force: request_tty should be SSH_REQUEST_TTY_FORCE */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "ttyforce");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_REQUEST_TTY, &request_tty);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(request_tty, SSH_REQUEST_TTY_FORCE);
}

/**
 * @brief Verify we can parse RequestTTY configuration option from string
 */
static void torture_config_request_tty_string(void **state)
{
    torture_config_request_tty(state, NULL, LIBSSH_TESTCONFIG_STRING22);
}

/**
 * @brief Verify we can parse RequestTTY configuration option from file
 */
static void torture_config_request_tty_file(void **state)
{
    torture_config_request_tty(state, LIBSSH_TESTCONFIG22, NULL);
}

/**
 * @brief Verify we can parse EscapeChar configuration option
 */
static void torture_config_escape_char(void **state,
                                       const char *file,
                                       const char *string)
{
    ssh_session session = *state;
    int result = 0;
    int rc = 0;

    /* EscapeChar ~: escape_char should be '~' */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "tildeescape");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_ESCAPE_CHAR, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, '~');

    /* EscapeChar ^C: escape_char should be 3 (Ctrl-C) */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "ctrlcescape");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_ESCAPE_CHAR, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, 3);

    /* EscapeChar none: escape_char should be -1 */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "noescape");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get_int(session, SSH_OPTIONS_ESCAPE_CHAR, &result);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(result, -1);
}

/**
 * @brief Verify we can parse EscapeChar configuration option from string
 */
static void torture_config_escape_char_string(void **state)
{
    torture_config_escape_char(state, NULL, LIBSSH_TESTCONFIG_STRING24);
}

/**
 * @brief Verify we can parse EscapeChar configuration option from file
 */
static void torture_config_escape_char_file(void **state)
{
    torture_config_escape_char(state, LIBSSH_TESTCONFIG24, NULL);
}

/**
 * @brief Verify we can parse LocalForward configuration option
 */
static void torture_config_local_forward(void **state,
                                         const char *file,
                                         const char *string)
{
    ssh_session session = *state;
    char *value = NULL;
    int rc = 0;

    /* Host withfwd: three LocalForward entries should be parsed */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "withfwd");
    _parse_config(session, file, string, SSH_OK);

    /* First entry: "8080 web:80" */
    rc = ssh_options_get(session, SSH_OPTIONS_LOCAL_FORWARD, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "8080 web:80");
    ssh_string_free_char(value);
    value = NULL;

    /* Second entry: "0.0.0.0:9090 db:3306" */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_LOCAL_FORWARD, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "0.0.0.0:9090 db:3306");
    ssh_string_free_char(value);
    value = NULL;

    /* Third entry: "/tmp/local.sock /tmp/remote.sock" (Unix domain socket) */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_LOCAL_FORWARD, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "/tmp/local.sock /tmp/remote.sock");
    ssh_string_free_char(value);
    value = NULL;

    /* Iterator should be exhausted after three entries */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_LOCAL_FORWARD, &value);
    assert_int_equal(rc, SSH_EOF);

    /* Host nofwd: no LocalForward lines so list should be empty */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "nofwd");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get(session, SSH_OPTIONS_LOCAL_FORWARD, &value);
    assert_int_equal(rc, SSH_ERROR);
}

/**
 * @brief Verify we can parse LocalForward configuration option from string
 */
static void torture_config_local_forward_string(void **state)
{
    torture_config_local_forward(state, NULL, LIBSSH_TESTCONFIG_STRING27);
}

/**
 * @brief Verify we can parse LocalForward configuration option from file
 */
static void torture_config_local_forward_file(void **state)
{
    torture_config_local_forward(state, LIBSSH_TESTCONFIG27, NULL);
}

/**
 * @brief Verify we can parse RemoteForward configuration option
 */
static void torture_config_remote_forward(void **state,
                                          const char *file,
                                          const char *string)
{
    ssh_session session = *state;
    char *value = NULL;
    int rc = 0;

    /* Host withrfwd: three RemoteForward entries should be parsed */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "withrfwd");
    _parse_config(session, file, string, SSH_OK);

    /* First entry: "8080 web:80" */
    rc = ssh_options_get(session, SSH_OPTIONS_REMOTE_FORWARD, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "8080 web:80");
    ssh_string_free_char(value);
    value = NULL;

    /* Second entry: "0.0.0.0:9090 db:3306" */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_REMOTE_FORWARD, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "0.0.0.0:9090 db:3306");
    ssh_string_free_char(value);
    value = NULL;

    /* Third entry: "/tmp/remote.sock /tmp/local.sock" (Unix domain socket) */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_REMOTE_FORWARD, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "/tmp/remote.sock /tmp/local.sock");
    ssh_string_free_char(value);
    value = NULL;

    /* Iterator should be exhausted after three entries */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_REMOTE_FORWARD, &value);
    assert_int_equal(rc, SSH_EOF);

    /* Host norfwd: no RemoteForward lines so list should be empty */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "norfwd");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get(session, SSH_OPTIONS_REMOTE_FORWARD, &value);
    assert_int_equal(rc, SSH_ERROR);
}

/**
 * @brief Verify we can parse RemoteForward configuration option from string
 */
static void torture_config_remote_forward_string(void **state)
{
    torture_config_remote_forward(state, NULL, LIBSSH_TESTCONFIG_STRING28);
}

/**
 * @brief Verify we can parse RemoteForward configuration option from file
 */
static void torture_config_remote_forward_file(void **state)
{
    torture_config_remote_forward(state, LIBSSH_TESTCONFIG28, NULL);
}

/**
 * @brief Verify we can parse SendEnv configuration option
 */
static void torture_config_send_env(void **state,
                                    const char *file,
                                    const char *string)
{
    ssh_session session = *state;
    char *value = NULL;
    int rc = 0;

    /* SendEnv LANG LC_* on matching host: three patterns should be stored */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "withenv");
    _parse_config(session, file, string, SSH_OK);

    /* First pattern: LANG */
    rc = ssh_options_get(session, SSH_OPTIONS_SEND_ENV, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "LANG");
    ssh_string_free_char(value);
    value = NULL;

    /* Second pattern: LC_* */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_SEND_ENV, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "LC_*");
    ssh_string_free_char(value);
    value = NULL;

    /* Third pattern: TZ */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_SEND_ENV, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "TZ");
    ssh_string_free_char(value);
    value = NULL;

    /* No more patterns: SSH_EOF */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_SEND_ENV, &value);
    assert_int_equal(rc, SSH_EOF);

    /* Host without SendEnv: getter will return error */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "noenv");
    _parse_config(session, file, string, SSH_OK);
    rc = ssh_options_get(session, SSH_OPTIONS_SEND_ENV, &value);
    assert_int_not_equal(rc, SSH_OK);

    /* SendEnv with negation: -LANG removes LANG, leaving LC_* and TZ */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "negenv");
    _parse_config(session, file, string, SSH_OK);

    /* First pattern should be LC_* (LANG was removed) */
    rc = ssh_options_get(session, SSH_OPTIONS_SEND_ENV, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "LC_*");
    ssh_string_free_char(value);
    value = NULL;

    /* Second pattern: TZ */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_SEND_ENV, &value);
    assert_int_equal(rc, SSH_OK);
    assert_string_equal(value, "TZ");
    ssh_string_free_char(value);
    value = NULL;

    /* No more patterns */
    rc = ssh_options_get(session, SSH_OPTIONS_NEXT_SEND_ENV, &value);
    assert_int_equal(rc, SSH_EOF);
}

/**
 * @brief Verify we can parse SendEnv configuration option from string
 */
static void torture_config_send_env_string(void **state)
{
    torture_config_send_env(state, NULL, LIBSSH_TESTCONFIG_STRING25);
}

/**
 * @brief Verify we can parse SendEnv configuration option from file
 */
static void torture_config_send_env_file(void **state)
{
    torture_config_send_env(state, LIBSSH_TESTCONFIG25, NULL);
}

/**
 * @brief Verify we can parse AdressFamily configuration option
 */
static void torture_config_address_family(void **state,
                                          const char *file,
                                          const char *string)
{
    ssh_session session = *state;

    const char *config = NULL;

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "simple");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.address_family, SSH_ADDRESS_FAMILY_ANY);

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "af");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.address_family, SSH_ADDRESS_FAMILY_ANY);

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "af4");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.address_family, SSH_ADDRESS_FAMILY_INET);

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "af6");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.address_family, SSH_ADDRESS_FAMILY_INET6);

    /* test for parsing failures */
    config = "Host afmissing\n"
             "\tAddressFamily\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "afmissing");
    _parse_config(session, file, string, SSH_ERROR);

    config = "Host afinvalid\n"
             "\tAddressFamily wurstkäse\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "afinvalid");
    _parse_config(session, file, string, SSH_ERROR);
}

/**
 * @brief Verify we can parse AdressFamily configuration option from string
 */
static void torture_config_address_family_string(void **state)
{
    torture_config_address_family(state, NULL, LIBSSH_TESTCONFIG_STRING18);
}

/**
 * @brief Verify we can parse AdressFamily configuration option from file
 */
static void torture_config_address_family_file(void **state)
{
    torture_config_address_family(state, LIBSSH_TESTCONFIG18, NULL);
}

/**
 * @brief Verify the configuration parser handles all the possible
 * versions of RekeyLimit configuration option.
 */
static void torture_config_rekey(void **state,
                                 const char *file, const char *string)
{
    ssh_session session = *state;
    const char *config = NULL;
    const uint64_t previous_rekey_data = 64;
    const int previous_rekey_time_ms = 42 * 60 * 1000;

    /* Default values */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "default");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data, 0);
    assert_int_equal(session->opts.rekey_time, 0);

    /* 42 GB */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "data1");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data,
            (uint64_t) 42 * 1024 * 1024 * 1024);
    assert_int_equal(session->opts.rekey_time, 0);

    /* 42 GB, 1h */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "datatime");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data,
                     (uint64_t)42 * 1024 * 1024 * 1024);
    assert_int_equal(session->opts.rekey_time, 60 * 60 * 1000);

    /* 41 MB */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "data2");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data, 31 * 1024 * 1024);
    assert_int_equal(session->opts.rekey_time, 0);

    /* 521 KB */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "data3");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data, 521 * 1024);
    assert_int_equal(session->opts.rekey_time, 0);

    /* 5k*n -> 5120 (Invalid suffix is ignored) */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "data4");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data, 5 * 1024);
    assert_int_equal(session->opts.rekey_time, 0);

    /* default 3D */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "time1");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data, 0);
    assert_int_equal(session->opts.rekey_time, 3 * 24 * 60 * 60 * 1000);

    /* default 2h */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "time2");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data, 0);
    assert_int_equal(session->opts.rekey_time, 2 * 60 * 60 * 1000);

    /* default 160m */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "time3");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data, 0);
    assert_int_equal(session->opts.rekey_time, 160 * 60 * 1000);

    /* default 9600 [s] */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "time4");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data, 0);
    assert_int_equal(session->opts.rekey_time, 9600 * 1000);

    config = "Host data-too-small\n"
             "\tRekeyLimit 1 1h\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }

    torture_reset_config(session);
    /* Invalid RekeyLimit values should leave the previous settings untouched.
     */
    session->opts.rekey_data = previous_rekey_data;
    session->opts.rekey_time = previous_rekey_time_ms;
    ssh_options_set(session, SSH_OPTIONS_HOST, "data-too-small");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data, previous_rekey_data);
    assert_int_equal(session->opts.rekey_time, previous_rekey_time_ms);

    config = "Host data-under-minimum\n"
             "\tRekeyLimit 15 none\n";
    if (file != NULL) {
        torture_write_file(file, config);
    } else {
        string = config;
    }

    torture_reset_config(session);
    session->opts.rekey_data = 128;
    session->opts.rekey_time = 21 * 60 * 1000;
    ssh_options_set(session, SSH_OPTIONS_HOST, "data-under-minimum");
    _parse_config(session, file, string, SSH_OK);
    assert_int_equal(session->opts.rekey_data, 128);
    assert_int_equal(session->opts.rekey_time, 21 * 60 * 1000);
}

/**
 * @brief Verify the configuration parser handles all the possible
 * versions of RekeyLimit configuration option in file
 */
static void torture_config_rekey_file(void **state)
{
    torture_config_rekey(state, LIBSSH_TESTCONFIG12, NULL);
}

/**
 * @brief Verify the configuration parser handles all the possible
 * versions of RekeyLimit configuration option in string
 */
static void torture_config_rekey_string(void **state)
{
    torture_config_rekey(state, NULL, LIBSSH_TESTCONFIG_STRING12);
}

static void torture_config_rekey_cli_optional_time(void **state)
{
    ssh_session session = *state;
    int rc;

    torture_reset_config(session);

    rc = ssh_config_parse_line_cli(session, "RekeyLimit 42G");
    assert_int_equal(rc, 0);
    assert_int_equal(session->opts.rekey_data,
                     (uint64_t)42 * 1024 * 1024 * 1024);
    assert_int_equal(session->opts.rekey_time, 0);
}

/**
 * @brief Remove substring from a string
 *
 * @param occurrence 0 means "remove the first occurrence"
 *                   1 means "remove the second occurrence" and so on
 */
static void helper_remove_substring(char *s, const char *subs, int occurrence) {
    char *p;
    /* remove the substring from the defaults */
    p = strstr(s, subs);
    assert_non_null(p);
    /* look for second occurrence */
    for (int i = 0; i < occurrence; i++) {
        p = strstr(p + 1, subs);
        assert_non_null(p);
    }
    memmove(p, p + strlen(subs), strlen(p + strlen(subs)) + 1);
}

/**
 * @brief test that openssh style '+' feature works
 */
static void torture_config_plus(void **state,
                                const char *file, const char *string)
{
    ssh_session session = *state;
    const char *def_hostkeys = ssh_kex_get_default_methods(SSH_HOSTKEYS);
    const char *fips_hostkeys = ssh_kex_get_fips_methods(SSH_HOSTKEYS);
    const char *def_ciphers = ssh_kex_get_default_methods(SSH_CRYPT_C_S);
    const char *fips_ciphers = ssh_kex_get_fips_methods(SSH_CRYPT_C_S);
    const char *def_kex = ssh_kex_get_default_methods(SSH_KEX);
    const char *fips_kex = ssh_kex_get_fips_methods(SSH_KEX);
    const char *def_mac = ssh_kex_get_default_methods(SSH_MAC_C_S);
    const char *fips_mac = ssh_kex_get_fips_methods(SSH_MAC_C_S);
    const char *hostkeys_added = ",ssh-rsa";
    const char *ciphers_added = ",aes128-cbc,aes256-cbc";
    const char *kex_added = ",diffie-hellman-group14-sha1,diffie-hellman-group1-sha1";
    const char *mac_added = ",hmac-sha1,hmac-sha1-etm@openssh.com";
    char *awaited = NULL;
    int rc;

    _parse_config(session, file, string, SSH_OK);

    /* check hostkeys */
    if (ssh_fips_mode()) {
        /* ssh-rsa is disabled in fips */
        assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS], fips_hostkeys);
    } else {
        awaited = calloc(strlen(def_hostkeys) + strlen(hostkeys_added) + 1, 1);
        rc = snprintf(awaited, strlen(def_hostkeys) + strlen(hostkeys_added) + 1,
                      "%s%s", def_hostkeys, hostkeys_added);
        assert_int_equal(rc, strlen(def_hostkeys) + strlen(hostkeys_added));

        assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS], awaited);
        free(awaited);
    }

    /* check ciphers */
    if (ssh_fips_mode()) {
        /* already all supported is in the list */
        assert_string_equal(session->opts.wanted_methods[SSH_CRYPT_C_S], fips_ciphers);
    } else {
        awaited = calloc(strlen(def_ciphers) + strlen(ciphers_added) + 1, 1);
        rc = snprintf(awaited, strlen(def_ciphers) + strlen(ciphers_added) + 1,
                      "%s%s", def_ciphers, ciphers_added);
        assert_int_equal(rc, strlen(def_ciphers) + strlen(ciphers_added));
        assert_string_equal(session->opts.wanted_methods[SSH_CRYPT_C_S], awaited);
        free(awaited);
    }

    /* check kex */
    if (ssh_fips_mode()) {
        /* sha1 is disabled in fips */
        assert_string_equal(session->opts.wanted_methods[SSH_KEX], fips_kex);
    } else {
        awaited = calloc(strlen(def_kex) + strlen(kex_added) + 1, 1);
        rc = snprintf(awaited, strlen(def_kex) + strlen(kex_added) + 1,
                      "%s%s", def_kex, kex_added);
        assert_int_equal(rc, strlen(def_kex) + strlen(kex_added));
        assert_string_equal(session->opts.wanted_methods[SSH_KEX], awaited);
        free(awaited);
    }

    /* check mac */
    if (ssh_fips_mode()) {
        /* the added algos are already in the fips_methods */
        assert_string_equal(session->opts.wanted_methods[SSH_MAC_C_S], fips_mac);
    } else {
        awaited = calloc(strlen(def_mac) + strlen(mac_added) + 1, 1);
        rc = snprintf(awaited, strlen(def_mac) + strlen(mac_added) + 1,
                      "%s%s", def_mac, mac_added);
        assert_int_equal(rc, strlen(def_mac) + strlen(mac_added));
        assert_string_equal(session->opts.wanted_methods[SSH_MAC_C_S], awaited);
        free(awaited);
    }
}

/**
 * @brief test that openssh style '+' feature works from file
 */
static void torture_config_plus_file(void **state)
{
    torture_config_plus(state, LIBSSH_TESTCONFIG14, NULL);
}

/**
 * @brief test that openssh style '+' feature works from string
 */
static void torture_config_plus_string(void **state)
{
    torture_config_plus(state, NULL, LIBSSH_TESTCONFIG_STRING14);
}

/**
 * @brief test that openssh style '-' feature works from string
 */
static void torture_config_minus(void **state,
                                 const char *file, const char *string)
{
    ssh_session session = *state;
    const char *def_hostkeys = ssh_kex_get_default_methods(SSH_HOSTKEYS);
    const char *fips_hostkeys = ssh_kex_get_fips_methods(SSH_HOSTKEYS);
    const char *def_ciphers = ssh_kex_get_default_methods(SSH_CRYPT_C_S);
    const char *fips_ciphers = ssh_kex_get_fips_methods(SSH_CRYPT_C_S);
    const char *def_kex = ssh_kex_get_default_methods(SSH_KEX);
    const char *fips_kex = ssh_kex_get_fips_methods(SSH_KEX);
    const char *def_mac = ssh_kex_get_default_methods(SSH_MAC_C_S);
    const char *fips_mac = ssh_kex_get_fips_methods(SSH_MAC_C_S);
    const char *hostkeys_removed = ",rsa-sha2-512,rsa-sha2-256";
    const char *ciphers_removed = ",aes256-ctr";
    const char *kex_removed = ",diffie-hellman-group18-sha512,diffie-hellman-group16-sha512";
    const char *fips_kex_removed = ",diffie-hellman-group16-sha512,diffie-hellman-group18-sha512";
    const char *mac_removed = "hmac-sha2-256-etm@openssh.com,";
    char *awaited = NULL;
    int rc;

    _parse_config(session, file, string, SSH_OK);

    /* check hostkeys */
    if (ssh_fips_mode()) {
        awaited = calloc(strlen(fips_hostkeys) + 1, 1);
        rc = snprintf(awaited, strlen(fips_hostkeys) + 1, "%s", fips_hostkeys);
        assert_int_equal(rc, strlen(fips_hostkeys));
    } else {
        awaited = calloc(strlen(def_hostkeys) + 1, 1);
        rc = snprintf(awaited, strlen(def_hostkeys) + 1, "%s", def_hostkeys);
        assert_int_equal(rc, strlen(def_hostkeys));
    }
    /* remove the substring from the defaults */
    helper_remove_substring(awaited, hostkeys_removed, 0);
    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS], awaited);
    free(awaited);

    /* check ciphers */
    if (ssh_fips_mode()) {
        awaited = calloc(strlen(fips_ciphers) + 1, 1);
        rc = snprintf(awaited, strlen(fips_ciphers) + 1, "%s", fips_ciphers);
        assert_int_equal(rc, strlen(fips_ciphers));
    } else {
        awaited = calloc(strlen(def_ciphers) + 1, 1);
        rc = snprintf(awaited, strlen(def_ciphers) + 1, "%s", def_ciphers);
        assert_int_equal(rc, strlen(def_ciphers));
    }
    /* remove the substring from the defaults */
    helper_remove_substring(awaited, ciphers_removed, 0);
    assert_string_equal(session->opts.wanted_methods[SSH_CRYPT_C_S], awaited);
    free(awaited);

    /* check kex */
    if (ssh_fips_mode()) {
        awaited = calloc(strlen(fips_kex) + 1, 1);
        rc = snprintf(awaited, strlen(fips_kex) + 1, "%s", fips_kex);
        assert_int_equal(rc, strlen(fips_kex));
        /* remove the substring from the defaults */
        helper_remove_substring(awaited, fips_kex_removed, 0);
    } else {
        awaited = calloc(strlen(def_kex) + 1, 1);
        rc = snprintf(awaited, strlen(def_kex) + 1, "%s", def_kex);
        assert_int_equal(rc, strlen(def_kex));
        /* remove the substring from the defaults */
        helper_remove_substring(awaited, kex_removed, 0);
    }
    assert_string_equal(session->opts.wanted_methods[SSH_KEX], awaited);
    free(awaited);

    /* check mac */
    if (ssh_fips_mode()) {
        awaited = calloc(strlen(fips_mac) + 1, 1);
        rc = snprintf(awaited, strlen(fips_mac) + 1, "%s", fips_mac);
        assert_int_equal(rc, strlen(fips_mac));
    } else {
        awaited = calloc(strlen(def_mac) + 1, 1);
        rc = snprintf(awaited, strlen(def_mac) + 1, "%s", def_mac);
        assert_int_equal(rc, strlen(def_mac));
    }
    /* remove the substring from the defaults */
    helper_remove_substring(awaited, mac_removed, 0);
    assert_string_equal(session->opts.wanted_methods[SSH_MAC_C_S], awaited);
    free(awaited);
}

/**
 * @brief test that openssh style '-' feature works from file
 */
static void torture_config_minus_file(void **state)
{
    torture_config_minus(state, LIBSSH_TESTCONFIG15, NULL);
}

/**
 * @brief test that openssh style '-' feature works from string
 */
static void torture_config_minus_string(void **state)
{
    torture_config_minus(state, NULL, LIBSSH_TESTCONFIG_STRING15);
}

/**
 * @brief test that openssh style '^' feature works from string
 */
static void torture_config_caret(void **state,
                                 const char *file, const char *string)
{
    ssh_session session = *state;
    const char *def_hostkeys = ssh_kex_get_default_methods(SSH_HOSTKEYS);
    const char *fips_hostkeys = ssh_kex_get_fips_methods(SSH_HOSTKEYS);
    const char *def_ciphers = ssh_kex_get_default_methods(SSH_CRYPT_C_S);
    const char *fips_ciphers = ssh_kex_get_fips_methods(SSH_CRYPT_C_S);
    const char *def_kex = ssh_kex_get_default_methods(SSH_KEX);
    const char *fips_kex = ssh_kex_get_fips_methods(SSH_KEX);
    const char *def_mac = ssh_kex_get_default_methods(SSH_MAC_C_S);
    const char *fips_mac = ssh_kex_get_fips_methods(SSH_MAC_C_S);
    const char *hostkeys_prio = "rsa-sha2-512,rsa-sha2-256";
    const char *ciphers_prio = "aes256-cbc,";
    const char *kex_prio = "diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,";
    const char *fips_kex_prio = ",diffie-hellman-group16-sha512,diffie-hellman-group18-sha512";
    const char *mac_prio = "hmac-sha1,";
    char *awaited = NULL;
    int rc;

    _parse_config(session, file, string, SSH_OK);

    /* check hostkeys */
    /* +2 for the added comma and the \0 */
    if (ssh_fips_mode()) {
        awaited = calloc(strlen(hostkeys_prio) + strlen(fips_hostkeys) + 2, 1);
        rc = snprintf(awaited, strlen(hostkeys_prio) + strlen(fips_hostkeys) + 2,
                      "%s,%s", hostkeys_prio, fips_hostkeys);
        assert_int_equal(rc, strlen(hostkeys_prio) + strlen(fips_hostkeys) + 1);
    } else {
        awaited = calloc(strlen(def_hostkeys) + strlen(hostkeys_prio) + 2, 1);
        rc = snprintf(awaited, strlen(hostkeys_prio) + strlen(def_hostkeys) + 2,
                      "%s,%s", hostkeys_prio, def_hostkeys);
        assert_int_equal(rc, strlen(hostkeys_prio) + strlen(def_hostkeys) + 1);
    }

    /* remove the substring from the defaults */
    helper_remove_substring(awaited, hostkeys_prio, 1);
    /* remove the comma at the end of the list */
    awaited[strlen(awaited) - 1] = '\0';

    assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS], awaited);
    free(awaited);

    /* check ciphers */
    if (ssh_fips_mode()) {
        awaited = calloc(strlen(ciphers_prio) + strlen(fips_ciphers) + 1, 1);
        rc = snprintf(awaited, strlen(ciphers_prio) + strlen(fips_ciphers) + 1,
                      "%s%s", ciphers_prio, fips_ciphers);
        assert_int_equal(rc, strlen(ciphers_prio) + strlen(fips_ciphers));
        /* remove the substring from the defaults */
        helper_remove_substring(awaited, ciphers_prio, 1);
    } else {
        /* + 2 because the '\0' and the comma */
        awaited = calloc(strlen(ciphers_prio) + strlen(def_ciphers) + 1, 1);
        rc = snprintf(awaited, strlen(ciphers_prio) + strlen(def_ciphers) + 1,
                      "%s%s", ciphers_prio, def_ciphers);
        assert_int_equal(rc, strlen(ciphers_prio) + strlen(def_ciphers));
    }

    assert_string_equal(session->opts.wanted_methods[SSH_CRYPT_C_S], awaited);
    free(awaited);

    /* check kex */
    if (ssh_fips_mode()) {
        awaited = calloc(strlen(kex_prio) + strlen(fips_kex) + 1, 1);
        rc = snprintf(awaited, strlen(kex_prio) + strlen(fips_kex) + 1,
                      "%s%s", kex_prio, fips_kex);
        assert_int_equal(rc, strlen(kex_prio) + strlen(fips_kex));
        /* remove the substring from the defaults */
        /* the default list has different order of these two algos than the fips
         * and because here is a braindead string substitution being done,
         * change the order and remove the first occurrence of it */
        helper_remove_substring(awaited, fips_kex_prio, 0);
    } else {
        awaited = calloc(strlen(kex_prio) + strlen(def_kex) + 1, 1);
        rc = snprintf(awaited, strlen(kex_prio) + strlen(def_kex) + 1,
                      "%s%s", kex_prio, def_kex);
        assert_int_equal(rc, strlen(def_kex) + strlen(kex_prio));
        /* remove the substring from the defaults */
        helper_remove_substring(awaited, kex_prio, 1);
    }

    assert_string_equal(session->opts.wanted_methods[SSH_KEX], awaited);
    free(awaited);

    /* check mac */
    if (ssh_fips_mode()) {
        awaited = calloc(strlen(mac_prio) + strlen(fips_mac) + 1, 1);
        rc = snprintf(awaited, strlen(mac_prio) + strlen(fips_mac) + 1, "%s%s", mac_prio, fips_mac);
        assert_int_equal(rc, strlen(mac_prio) + strlen(fips_mac));
        /* the fips list contains hmac-sha1 algo */
        helper_remove_substring(awaited, mac_prio, 1);
    } else {
        awaited = calloc(strlen(mac_prio) + strlen(def_mac) + 1, 1);
        /* the mac is not in default; it is added to the list */
        rc = snprintf(awaited, strlen(mac_prio) + strlen(def_mac) + 1, "%s%s", mac_prio, def_mac);
        assert_int_equal(rc, strlen(mac_prio) + strlen(def_mac));
    }
    assert_string_equal(session->opts.wanted_methods[SSH_MAC_C_S], awaited);
    free(awaited);
}

/**
 * @brief test that openssh style '^' feature works from file
 */
static void torture_config_caret_file(void **state)
{
    torture_config_caret(state, LIBSSH_TESTCONFIG16, NULL);
}

/**
 * @brief test that openssh style '^' feature works from string
 */
static void torture_config_caret_string(void **state)
{
    torture_config_caret(state, NULL, LIBSSH_TESTCONFIG_STRING16);
}

/**
 * @brief test PubkeyAcceptedKeyTypes helper function
 */
static void torture_config_pubkeytypes(void **state,
                                       const char *file, const char *string)
{
    ssh_session session = *state;
    char *fips_algos;

    _parse_config(session, file, string, SSH_OK);

    if (ssh_fips_mode()) {
        fips_algos = ssh_keep_fips_algos(SSH_HOSTKEYS, PUBKEYACCEPTEDTYPES);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.pubkey_accepted_types, fips_algos);
        SAFE_FREE(fips_algos);
    } else {
        assert_string_equal(session->opts.pubkey_accepted_types,
                PUBKEYACCEPTEDTYPES);
    }
}

/**
 * @brief test parsing PubkeyAcceptedKeyTypes from file
 */
static void torture_config_pubkeytypes_file(void **state)
{
    torture_config_pubkeytypes(state, LIBSSH_TEST_PUBKEYTYPES, NULL);
}

/**
 * @brief test parsing PubkeyAcceptedKeyTypes from string
 */
static void torture_config_pubkeytypes_string(void **state)
{
    torture_config_pubkeytypes(state, NULL, LIBSSH_TEST_PUBKEYTYPES_STRING);
}

/**
 * @brief test parsing PubkeyAcceptedKAlgorithms from file
 */
static void torture_config_pubkeyalgorithms_file(void **state)
{
    torture_config_pubkeytypes(state, LIBSSH_TEST_PUBKEYALGORITHMS, NULL);
}

/**
 * @brief test parsing PubkeyAcceptedAlgorithms from string
 */
static void torture_config_pubkeyalgorithms_string(void **state)
{
    torture_config_pubkeytypes(state, NULL, LIBSSH_TEST_PUBKEYALGORITHMS_STRING);
}

/**
 * @brief Verify the configuration parser handles
 * missing newline in the end
 */
static void torture_config_nonewlineend(void **state,
                                        const char *file, const char *string)
{
    _parse_config(*state, file, string, SSH_OK);
}

/**
 * @brief Verify the configuration parser handles
 * missing newline in the end of file
 */
static void torture_config_nonewlineend_file(void **state)
{
    torture_config_nonewlineend(state, LIBSSH_TEST_NONEWLINEEND, NULL);
}

/**
 * @brief Verify the configuration parser handles
 * missing newline in the end of string
 */
static void torture_config_nonewlineend_string(void **state)
{
    torture_config_nonewlineend(state, NULL, LIBSSH_TEST_NONEWLINEEND_STRING);
}

/**
 * @brief Verify the configuration parser handles
 * missing newline in the end
 */
static void torture_config_nonewlineoneline(void **state,
                                            const char *file,
                                            const char *string)
{
    _parse_config(*state, file, string, SSH_OK);
}

/**
 * @brief Verify the configuration parser handles
 * missing newline in the end of file
 */
static void torture_config_nonewlineoneline_file(void **state)
{
    torture_config_nonewlineend(state, LIBSSH_TEST_NONEWLINEONELINE, NULL);
}

/**
 * @brief Verify the configuration parser handles
 * missing newline in the end of string
 */
static void torture_config_nonewlineoneline_string(void **state)
{
    torture_config_nonewlineoneline(state,
            NULL, LIBSSH_TEST_NONEWLINEONELINE_STRING);
}

/* ssh_config_get_cmd() does these two things:
 *  * Strips leading whitespace
 *  * Terminate on the end of line
 */
static void torture_config_parser_get_cmd(void **state)
{
    char *p = NULL, *tok = NULL;
    char data[256];
#ifdef WITH_EXEC
    FILE *outfile = NULL, *infile = NULL;
    int pid;
    char buffer[256] = {0};
#endif
    (void)state;

    /* Ignore leading whitespace */
    strlcpy(data, "  \t\t  string\n", sizeof(data));
    p = data;
    tok = ssh_config_get_cmd(&p);
    assert_string_equal(tok, "string");
    assert_int_equal(*p, '\0');

    /* but keeps the trailing whitespace */
    strlcpy(data, "string  \t\t  \n", sizeof(data));
    p = data;
    tok = ssh_config_get_cmd(&p);
    assert_string_equal(tok, "string  \t\t  ");
    assert_int_equal(*p, '\0');

    /* should not drop the quotes and not split them into separate arguments */
    strlcpy(data, "\"multi string\" something\n", sizeof(data));
    p = data;
    tok = ssh_config_get_cmd(&p);
    assert_string_equal(tok, "\"multi string\" something");
    assert_int_equal(*p, '\0');

    /* But it does not split tokens by whitespace
     * if they are not quoted, which is weird */
    strlcpy(data, "multi string something\n", sizeof(data));
    p = data;
    tok = ssh_config_get_cmd(&p);
    assert_string_equal(tok, "multi string something");
    assert_int_equal(*p, '\0');

    /* Commands in quotes are not treated special */
    sprintf(data, "%s%s%s%s", "\"", SOURCEDIR "/tests/unittests/hello world.sh", "\" ", "\"hello libssh\"\n");
    printf("%s\n", data);
    p = data;
    tok = ssh_config_get_cmd(&p);
    assert_string_equal(tok, data);
    assert_int_equal(*p, '\0');

#ifdef WITH_EXEC
    /* Check if the command would get correctly executed
     * Use the script file "hello world.sh" to echo the first argument
     * Run as <= "/workdir/hello world.sh" "hello libssh" => */

    /* output to file and check wrong */
    outfile = fopen("output.log", "a+");
    assert_non_null(outfile);
    printf("the tok is %s\n", tok);

    pid = fork();
    if (pid == -1) {
        perror("fork");
    } else if (pid == 0) {
        ssh_execute_command(tok, fileno(outfile), fileno(outfile));
        /* Does not return */
    } else {
        /* parent
         * wait child process */
        wait(NULL);
        infile = fopen("output.log", "r");
        assert_non_null(infile);
        p = fgets(buffer, sizeof(buffer), infile);
        fclose(infile);
        remove("output.log");
        assert_non_null(p);
    }

    fclose(outfile);
    assert_string_equal(buffer, "hello libssh");
#endif /* WITH_EXEC */
}

/* ssh_config_get_token() should behave as expected
 *  * Strip leading whitespace
 *  * Return first token separated by whitespace or equal sign,
 *    respecting quotes!
 *  * Correctly treat escaped quotes inside of quotes.
 */
static void torture_config_parser_get_token(void **state)
{
    char *p = NULL, *tok = NULL;
    char data[256];

    (void)state;

    /* Ignore leading whitespace (from get_cmd() already */
    strlcpy(data, "  \t\t  string\n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "string");
    assert_int_equal(*p, '\0');

    strlcpy(data, "  \t\t  string", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "string");
    assert_int_equal(*p, '\0');

    /* drops trailing whitespace */
    strlcpy(data, "string  \t\t  \n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "string");
    assert_int_equal(*p, '\0');

    strlcpy(data, "string  \t\t  ", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "string");
    assert_int_equal(*p, '\0');

    /* Correctly handles tokens in quotes */
    strlcpy(data, "\"multi string\" something\n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "multi string");
    assert_int_equal(*p, 's');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "something");
    assert_int_equal(*p, '\0');

    strlcpy(data, "\"multi string\" something", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "multi string");
    assert_int_equal(*p, 's');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "something");
    assert_int_equal(*p, '\0');

    /* Consistently splits unquoted strings */
    strlcpy(data, "multi string something\n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "multi");
    assert_int_equal(*p, 's');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "string");
    assert_int_equal(*p, 's');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "something");
    assert_int_equal(*p, '\0');

    strlcpy(data, "multi string something", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "multi");
    assert_int_equal(*p, 's');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "string");
    assert_int_equal(*p, 's');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "something");
    assert_int_equal(*p, '\0');

    /* It is made to parse also option=value pairs as well */
    strlcpy(data, "  key=value  \n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "key");
    assert_int_equal(*p, 'v');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "value");
    assert_int_equal(*p, '\0');

    strlcpy(data, "  key=value  ", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "key");
    assert_int_equal(*p, 'v');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "value");
    assert_int_equal(*p, '\0');

    /* spaces are allowed also around the equal sign */
    strlcpy(data, "  key  =  value  \n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "key");
    assert_int_equal(*p, 'v');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "value");
    assert_int_equal(*p, '\0');

    strlcpy(data, "  key  =  value  ", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "key");
    assert_int_equal(*p, 'v');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "value");
    assert_int_equal(*p, '\0');

    /* correctly parses even key=value pairs with either one in quotes */
    strlcpy(data, "  key=\"value with spaces\" \n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "key");
    assert_int_equal(*p, '\"');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "value with spaces");
    assert_int_equal(*p, '\0');

    strlcpy(data, "  key=\"value with spaces\" ", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "key");
    assert_int_equal(*p, '\"');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "value with spaces");
    assert_int_equal(*p, '\0');

    /* Escaped whitespace outside quotes stays within the same token. */
    strncpy(data, "tag\\ name something\n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "tag name");
    assert_int_equal(*p, 's');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "something");
    assert_int_equal(*p, '\0');

    /* Only one equal sign is allowed */
    strlcpy(data, "key==value\n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "key");
    assert_int_equal(*p, '=');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "");
    assert_int_equal(*p, 'v');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "value");
    assert_int_equal(*p, '\0');

    strlcpy(data, "key==value", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "key");
    assert_int_equal(*p, '=');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "");
    assert_int_equal(*p, 'v');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "value");
    assert_int_equal(*p, '\0');

    /* Unmatched quotes */
    strlcpy(data, " \"value\n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "value");
    assert_int_equal(*p, '\0');

    strlcpy(data, " \"value", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "value");
    assert_int_equal(*p, '\0');

    /* Escaped quotes */
    strlcpy(data, " \"value with \\\"escaped\\\" quotes\"   \n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "value with \"escaped\" quotes");
    assert_int_equal(*p, '\0');

    strlcpy(data, "\\\"value with \\\"escaped\\\" quotes\\\"\n", sizeof(data));
    p = data;
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "\"value");
    assert_int_equal(*p, 'w');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "with");
    assert_int_equal(*p, '\\');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "\"escaped\"");
    assert_int_equal(*p, 'q');
    tok = ssh_config_get_token(&p);
    assert_string_equal(tok, "quotes\"");
    assert_int_equal(*p, '\0');
}

static void torture_config_parser_get_token_info(void **state)
{
    struct ssh_config_token_info info;
    char *p = NULL, *tok = NULL;
    char data[256];

    (void)state;

    strncpy(data, "key=tag\\ name\n", sizeof(data));
    p = data;
    tok = ssh_config_get_token_info(&p, &info);
    assert_string_equal(tok, "key");
    assert_true(info.found);
    assert_true(info.had_equal);
    assert_false(info.invalid);
    tok = ssh_config_get_token_info(&p, &info);
    assert_string_equal(tok, "tag name");
    assert_true(info.found);
    assert_false(info.had_equal);
    assert_false(info.invalid);
    assert_int_equal(*p, '\0');

    strncpy(data, "key=\n", sizeof(data));
    p = data;
    tok = ssh_config_get_token_info(&p, &info);
    assert_string_equal(tok, "key");
    assert_true(info.found);
    assert_true(info.had_equal);
    assert_false(info.invalid);
    tok = ssh_config_get_token_info(&p, &info);
    assert_string_equal(tok, "");
    assert_false(info.found);
    assert_false(info.had_equal);
    assert_false(info.invalid);

    strncpy(data, "key \"\"\n", sizeof(data));
    p = data;
    tok = ssh_config_get_token_info(&p, &info);
    assert_string_equal(tok, "key");
    assert_true(info.found);
    assert_false(info.had_equal);
    assert_false(info.invalid);
    tok = ssh_config_get_token_info(&p, &info);
    assert_string_equal(tok, "");
    assert_true(info.found);
    assert_false(info.had_equal);
    assert_false(info.invalid);

    strncpy(data, "\"unterminated\n", sizeof(data));
    p = data;
    tok = ssh_config_get_token_info(&p, &info);
    assert_string_equal(tok, "unterminated");
    assert_true(info.found);
    assert_false(info.had_equal);
    assert_true(info.invalid);
}

static void torture_config_parser_get_yesno(void **state)
{
    char *p = NULL;
    char data[256];

    (void)state;

    strncpy(data, "yes\n", sizeof(data));
    p = data;
    assert_int_equal(ssh_config_get_yesno(&p, -1), 1);
    assert_int_equal(*p, '\0');

    strncpy(data, "NO\n", sizeof(data));
    p = data;
    assert_int_equal(ssh_config_get_yesno(&p, -1), 0);
    assert_int_equal(*p, '\0');

    strncpy(data, "true\n", sizeof(data));
    p = data;
    assert_int_equal(ssh_config_get_yesno(&p, -1), 1);
    assert_int_equal(*p, '\0');

    strncpy(data, "FALSE\n", sizeof(data));
    p = data;
    assert_int_equal(ssh_config_get_yesno(&p, -1), 0);
    assert_int_equal(*p, '\0');

    strncpy(data, "yesplease\n", sizeof(data));
    p = data;
    assert_int_equal(ssh_config_get_yesno(&p, -1), -1);
    assert_int_equal(*p, '\0');

    strncpy(data, "nope\n", sizeof(data));
    p = data;
    assert_int_equal(ssh_config_get_yesno(&p, -1), -1);
    assert_int_equal(*p, '\0');

    strncpy(data, "\n", sizeof(data));
    p = data;
    assert_int_equal(ssh_config_get_yesno(&p, -1), -1);
    assert_int_equal(*p, '\0');
}

/* match_pattern() sanity tests
 */
static void torture_config_match_pattern(void **state)
{
    int rv = 0;

    (void) state;

    /* Simple test "a" matches "a" */
    rv = match_pattern("a", "a");
    assert_int_equal(rv, 1);

    /* Simple test "a" does not match "b" */
    rv = match_pattern("a", "b");
    assert_int_equal(rv, 0);

    /* NULL arguments are correctly handled */
    rv = match_pattern("a", NULL);
    assert_int_equal(rv, 0);
    rv = match_pattern(NULL, "a");
    assert_int_equal(rv, 0);

    /* Simple wildcard ? is handled in pattern */
    rv = match_pattern("a", "?");
    assert_int_equal(rv, 1);
    rv = match_pattern("aa", "?");
    assert_int_equal(rv, 0);
    /* Wildcard in search string */
    rv = match_pattern("?", "a");
    assert_int_equal(rv, 0);
    rv = match_pattern("?", "?");
    assert_int_equal(rv, 1);

    /* Simple wildcard * is handled in pattern */
    rv = match_pattern("a", "*");
    assert_int_equal(rv, 1);
    rv = match_pattern("aa", "*");
    assert_int_equal(rv, 1);
    /* Wildcard in search string */
    rv = match_pattern("*", "a");
    assert_int_equal(rv, 0);
    rv = match_pattern("*", "*");
    assert_int_equal(rv, 1);

    /* More complicated patterns */
    rv = match_pattern("a", "*a");
    assert_int_equal(rv, 1);
    rv = match_pattern("a", "a*");
    assert_int_equal(rv, 1);
    rv = match_pattern("abababc", "*abc");
    assert_int_equal(rv, 1);
    rv = match_pattern("ababababca", "*abc");
    assert_int_equal(rv, 0);
    rv = match_pattern("ababababca", "*abc*");
    assert_int_equal(rv, 1);

    /* Multiple wildcards in row */
    rv = match_pattern("aa", "??");
    assert_int_equal(rv, 1);
    rv = match_pattern("bba", "??a");
    assert_int_equal(rv, 1);
    rv = match_pattern("aaa", "**a");
    assert_int_equal(rv, 1);
    rv = match_pattern("bbb", "**a");
    assert_int_equal(rv, 0);

    /* Consecutive asterisks do not make sense and do not need to recurse */
    rv = match_pattern("hostname", "**********pattern");
    assert_int_equal(rv, 0);
    rv = match_pattern("hostname", "pattern**********");
    assert_int_equal(rv, 0);
    rv = match_pattern("pattern", "***********pattern");
    assert_int_equal(rv, 1);
    rv = match_pattern("pattern", "pattern***********");
    assert_int_equal(rv, 1);

    rv = match_pattern("hostname", "*p*a*t*t*e*r*n*");
    assert_int_equal(rv, 0);
    rv = match_pattern("pattern", "*p*a*t*t*e*r*n*");
    assert_int_equal(rv, 1);

    /* Regular Expression Denial of Service */
    rv = match_pattern("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                       "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a");
    assert_int_equal(rv, 1);
    rv = match_pattern("ababababababababababababababababababababab",
                       "*a*b*a*b*a*b*a*b*a*b*a*b*a*b*a*b");
    assert_int_equal(rv, 1);

    /* A lot of backtracking */
    rv = match_pattern("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax",
                       "a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*ax");
    assert_int_equal(rv, 1);

    /* Test backtracking: *a matches first 'a', fails on 'b', must backtrack */
    rv = match_pattern("axaxaxb", "*a*b");
    assert_int_equal(rv, 1);

    /* Test greedy consumption with suffix */
    rv = match_pattern("foo_bar_baz_bar", "*bar");
    assert_int_equal(rv, 1);

    /* Test exact suffix requirement (ensure no partial match acceptance) */
    rv = match_pattern("foobar_extra", "*bar");
    assert_int_equal(rv, 0);

    /* Test multiple distinct wildcards */
    rv = match_pattern("a_very_long_string_with_a_pattern", "*long*pattern");
    assert_int_equal(rv, 1);

    /* ? inside a * sequence */
    rv = match_pattern("abcdefg", "a*c?e*g");
    assert_int_equal(rv, 1);

    /* Consecutive mixed wildcards */
    rv = match_pattern("abc", "*?c");
    assert_int_equal(rv, 1);

    /* ? at the very end after * */
    rv = match_pattern("abc", "ab?");
    assert_int_equal(rv, 1);
    rv = match_pattern("abc", "ab*?");
    assert_int_equal(rv, 1);

    /* Consecutive stars should be collapsed or handled gracefully */
    rv = match_pattern("abc", "a**c");
    assert_int_equal(rv, 1);
    rv = match_pattern("abc", "***");
    assert_int_equal(rv, 1);

    /* Empty string handling */
    rv = match_pattern("", "*");
    assert_int_equal(rv, 1);
    rv = match_pattern("", "?");
    assert_int_equal(rv, 0);
    rv = match_pattern("", "");
    assert_int_equal(rv, 1);

    /* Pattern longer than string */
    rv = match_pattern("short", "short_but_longer");
    assert_int_equal(rv, 0);
}

/* Identity file can be specified multiple times in the configuration
 */
static void torture_config_identity(void **state)
{
    const char *id = NULL;
    const char *cert = NULL;
    struct ssh_iterator *it = NULL;
    ssh_session session = *state;

    _parse_config(session, NULL, LIBSSH_TESTCONFIG_STRING13, SSH_OK);

    /* The identities are first added to this temporary list before expanding */
    it = ssh_list_get_iterator(session->opts.identity_non_exp);
    assert_non_null(it);
    id = it->data;
    /* The identities are prepended to the list so we start with second one */
    assert_string_equal(id, "id_ecdsa_two");

    it = it->next;
    assert_non_null(it);
    id = it->data;
    assert_string_equal(id, "id_rsa_one");

    /* The certs are first added to this temporary list before expanding */
    it = ssh_list_get_iterator(session->opts.certificate_non_exp);
    assert_non_null(it);
    cert = it->data;
    /* The certs are coming as listed in the configuration file */
    assert_string_equal(cert, "id_rsa_one-cert.pub");

    it = it->next;
    assert_non_null(it);
    cert = it->data;
    assert_string_equal(cert, "id_ecdsa_two-cert.pub");
    /* and that is all */
    assert_null(it->next);
}

/* Make absolute path for config include
 */
static void torture_config_make_absolute_int(void **state, bool no_sshdir_fails)
{
    ssh_session session = *state;
    char *result = NULL;
#ifndef _WIN32
    char h[256] = {0};
    char *user = NULL;
    char *home = NULL;
    struct passwd *pw = getpwuid(getuid());
    assert_non_null(pw);
    user = strdup(pw->pw_name);
    assert_non_null(user);
    home = strdup(pw->pw_dir);
    assert_non_null(home);
#endif

    /* Absolute path already -- should not change in any case */
    result = ssh_config_make_absolute(session, "/etc/ssh/ssh_config.d/*.conf", 1);
    assert_string_equal(result, "/etc/ssh/ssh_config.d/*.conf");
    free(result);
    result = ssh_config_make_absolute(session, "/etc/ssh/ssh_config.d/*.conf", 0);
    assert_string_equal(result, "/etc/ssh/ssh_config.d/*.conf");
    free(result);

    /* Global is relative to /etc/ssh/ */
    result = ssh_config_make_absolute(session, "ssh_config.d/test.conf", 1);
    assert_string_equal(result, "/etc/ssh/ssh_config.d/test.conf");
    free(result);
    result = ssh_config_make_absolute(session, "./ssh_config.d/test.conf", 1);
    assert_string_equal(result, "/etc/ssh/./ssh_config.d/test.conf");
    free(result);

    /* User config is relative to sshdir -- here faked to /tmp/ssh/ */
    result = ssh_config_make_absolute(session, "my_config", 0);
    if (no_sshdir_fails) {
        assert_null(result);
    } else {
        /* The path depends on the PWD so lets skip checking the actual path here */
        assert_non_null(result);
    }
    free(result);

    /* User config is relative to sshdir -- here faked to /tmp/ssh/ */
    ssh_options_set(session, SSH_OPTIONS_SSH_DIR, "/tmp/ssh");
    result = ssh_config_make_absolute(session, "my_config", 0);
    assert_string_equal(result, "/tmp/ssh/my_config");
    free(result);

#ifndef _WIN32
    /* Tilde expansion works only in user config */
    result = ssh_config_make_absolute(session, "~/.ssh/config.d/*.conf", 0);
    snprintf(h, 256 - 1, "%s/.ssh/config.d/*.conf", home);
    assert_string_equal(result, h);
    free(result);

    snprintf(h, 256 - 1, "~%s/.ssh/config.d/*.conf", user);
    result = ssh_config_make_absolute(session, h, 0);
    snprintf(h, 256 - 1, "%s/.ssh/config.d/*.conf", home);
    assert_string_equal(result, h);
    free(result);

    /* in global config its just prefixed without expansion */
    result = ssh_config_make_absolute(session, "~/.ssh/config.d/*.conf", 1);
    assert_string_equal(result, "/etc/ssh/~/.ssh/config.d/*.conf");
    free(result);
    snprintf(h, 256 - 1, "~%s/.ssh/config.d/*.conf", user);
    result = ssh_config_make_absolute(session, h, 1);
    snprintf(h, 256 - 1, "/etc/ssh/~%s/.ssh/config.d/*.conf", user);
    assert_string_equal(result, h);
    free(result);
    free(home);
    free(user);
#endif
}

static void torture_config_make_absolute(void **state)
{
    torture_config_make_absolute_int(state, 0);
}

static void torture_config_make_absolute_no_sshdir(void **state)
{
    torture_config_make_absolute_int(state, 1);
}

static void torture_config_parse_uri(void **state)
{
    char *username = NULL;
    char *hostname = NULL;
    char *port = NULL;
    int rc;

    (void)state; /* unused */

    rc = ssh_config_parse_uri("localhost",
                              &username,
                              &hostname,
                              &port,
                              false,
                              true);
    assert_return_code(rc, errno);
    assert_null(username);
    assert_string_equal(hostname, "localhost");
    SAFE_FREE(hostname);
    assert_null(port);

    rc = ssh_config_parse_uri("1.2.3.4",
                              &username,
                              &hostname,
                              &port,
                              false,
                              true);
    assert_return_code(rc, errno);
    assert_null(username);
    assert_string_equal(hostname, "1.2.3.4");
    SAFE_FREE(hostname);
    assert_null(port);

    rc = ssh_config_parse_uri("1.2.3.4:2222",
                              &username,
                              &hostname,
                              &port,
                              false,
                              true);
    assert_return_code(rc, errno);
    assert_null(username);
    assert_string_equal(hostname, "1.2.3.4");
    SAFE_FREE(hostname);
    assert_string_equal(port, "2222");
    SAFE_FREE(port);

    rc = ssh_config_parse_uri("[1:2:3::4]:2222",
                              &username,
                              &hostname,
                              &port,
                              false,
                              true);
    assert_return_code(rc, errno);
    assert_null(username);
    assert_string_equal(hostname, "1:2:3::4");
    SAFE_FREE(hostname);
    assert_string_equal(port, "2222");
    SAFE_FREE(port);

    /* do not want port */
    rc = ssh_config_parse_uri("1:2:3::4",
                              &username,
                              &hostname,
                              NULL,
                              true,
                              true);
    assert_return_code(rc, errno);
    assert_null(username);
    assert_string_equal(hostname, "1:2:3::4");
    SAFE_FREE(hostname);

    rc = ssh_config_parse_uri("user -name@", &username, NULL, NULL, true, true);
    assert_int_equal(rc, SSH_ERROR);

    /* Non-strict accepts non-RFC1035 chars (e.g. _, %) */
    rc = ssh_config_parse_uri("customer_1",
                              &username,
                              &hostname,
                              NULL,
                              true,
                              false);
    assert_return_code(rc, errno);
    assert_null(username);
    assert_string_equal(hostname, "customer_1");
    SAFE_FREE(hostname);

    rc = ssh_config_parse_uri("admin@%prod",
                              &username,
                              &hostname,
                              NULL,
                              true,
                              false);
    assert_return_code(rc, errno);
    assert_string_equal(username, "admin");
    assert_string_equal(hostname, "%prod");
    SAFE_FREE(username);
    SAFE_FREE(hostname);

    /* Strict rejects what non-strict accepts */
    rc = ssh_config_parse_uri("customer_1",
                              &username,
                              &hostname,
                              NULL,
                              true,
                              true);
    assert_int_equal(rc, SSH_ERROR);

    /* Non-strict rejects shell metacharacters */
    rc = ssh_config_parse_uri("host;cmd",
                              &username,
                              &hostname,
                              NULL,
                              true,
                              false);
    assert_int_equal(rc, SSH_ERROR);

    /* Non-strict rejects leading dash */
    rc = ssh_config_parse_uri("-host", &username, &hostname, NULL, true, false);
    assert_int_equal(rc, SSH_ERROR);
}

/* Complex ssh match configurations
 */
static void torture_config_match_complex(void **state)
{
    ssh_session session = *state;
    char *v = NULL;
    int ret;

    ssh_options_set(session, SSH_OPTIONS_HOST, "Bar");

    _parse_config(session, LIBSSH_TESTCONFIG_MATCH_COMPLEX, NULL, SSH_OK);

    /* Test the variable presence */
    ret = ssh_options_get(session, SSH_OPTIONS_HOST, &v);
    assert_return_code(ret, errno);
    assert_non_null(v);
#ifndef WITH_EXEC
    assert_string_equal(session->opts.host, "Bar");
#else
    assert_string_equal(v, "complex-match");
#endif
    ssh_string_free_char(v);
}

/* Missing value to LogLevel configuration option
 */
static void torture_config_loglevel_missing_value(void **state)
{
    ssh_session session = *state;

    ssh_options_set(session, SSH_OPTIONS_HOST, "Bar");

    _parse_config(session, LIBSSH_TESTCONFIG_LOGLEVEL_MISSING, NULL, SSH_OK);
}

static int before_connection(ssh_session jump_session, void *user)
{
    char *v = NULL;
    int ret;

    (void)user;

    /* During the connection, we force parsing the same configuration file
     * (would be normally parsed automatically during the connection itself)
     */
    ret = ssh_config_parse_file(jump_session, LIBSSH_TESTCONFIG_JUMP);
    assert_return_code(ret, errno);

    /* Test the variable presence */
    ret = ssh_options_get(jump_session, SSH_OPTIONS_HOST, &v);
    assert_return_code(ret, errno);
    assert_string_equal(v, "1xxxxxx");
    ssh_string_free_char(v);

    ret = ssh_options_get(jump_session, SSH_OPTIONS_USER, &v);
    assert_return_code(ret, errno);
    assert_string_equal(v, "ubuntu");
    ssh_string_free_char(v);

    assert_int_equal(jump_session->opts.port, 23);

    /* Fail the connection -- we are in unit tests so it would fail anyway */
    return 1;
}

static int verify_knownhost(ssh_session jump_session, void *user)
{
    (void)jump_session;
    (void)user;

    return 0;
}

static int authenticate(ssh_session jump_session, void *user)
{
    (void)jump_session;
    (void)user;

    return 0;
}
/* Reproducer for complex proxy jump
 */
static void torture_config_jump(void **state)
{
    ssh_session session = *state;
    struct ssh_jump_callbacks_struct c = {
        .before_connection = before_connection,
        .verify_knownhost = verify_knownhost,
        .authenticate = authenticate,
    };
    char *v = NULL;
    int ret;

    ssh_options_set(session, SSH_OPTIONS_HOST, "cisco-router");

    _parse_config(session, LIBSSH_TESTCONFIG_JUMP, NULL, SSH_OK);

    /* Test the variable presence */
    ret = ssh_options_get(session, SSH_OPTIONS_HOST, &v);
    assert_return_code(ret, errno);
    assert_string_equal(v, "xx.xxxxxxxxx");
    ssh_string_free_char(v);

    ret = ssh_options_get(session, SSH_OPTIONS_USER, &v);
    assert_return_code(ret, errno);
    assert_string_equal(v, "username");
    ssh_string_free_char(v);

    assert_int_equal(session->opts.port, 5555);

    /* At this point, the configuration file is not parsed for the jump host so
     * we are getting just the the hostname -- the port and username will get
     * pulled during the session connecting to this host */
    assert_int_equal(ssh_list_count(session->opts.proxy_jumps), 1);
    helper_proxy_jump_check(session->opts.proxy_jumps->root,
                            "ub-jumphost",
                            NULL,
                            NULL);

    /* Set up the callbacks -- they should verify we are going to connect to the
     * right host */
    ret = ssh_options_set(session, SSH_OPTIONS_PROXYJUMP_CB_LIST_APPEND, &c);
    assert_ssh_return_code(session, ret);

    ret = ssh_connect(session);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    printf("%s: EOF\n", __func__);
}

/* Verify Hostname directive resolves host without overwriting originalhost
 */
static void torture_config_hostname(void **state)
{
    ssh_session session = *state;
    char *expanded = NULL;

    /* Hostname directive sets host, originalhost is unchanged */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my_alias");
    assert_null(session->opts.host);
    assert_string_equal(session->opts.originalhost, "my_alias");
    _parse_config(session,
                  NULL,
                  "Host my_alias\n\tHostname 192.168.1.1\n",
                  SSH_OK);
    assert_string_equal(session->opts.host, "192.168.1.1");
    assert_string_equal(session->opts.originalhost, "my_alias");

    /* Hostname expands %h */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my-alias");
    assert_string_equal(session->opts.host, "my-alias");
    assert_string_equal(session->opts.originalhost, "my-alias");
    _parse_config(session,
                  NULL,
                  "Host my-alias\n\tHostname %h.ExAmPlE.CoM\n",
                  SSH_OK);
    assert_string_equal(session->opts.host, "my-alias.ExAmPlE.CoM");
    assert_string_equal(session->opts.originalhost, "my-alias");
    assert_int_equal(ssh_options_apply(session), SSH_OK);
    assert_string_equal(session->opts.host, "my-alias.example.com");
    assert_string_equal(session->opts.originalhost, "my-alias");

    /* Hostname %h parses on a fresh session but apply still requires a host */
    torture_reset_config(session);
    SAFE_FREE(session->opts.host);
    SAFE_FREE(session->opts.originalhost);
    assert_null(session->opts.host);
    assert_null(session->opts.originalhost);
    _parse_config(session, NULL, "HostName MiXeD-%h.ExAmPlE.CoM\n", SSH_OK);
    assert_string_equal(session->opts.config_hostname, "MiXeD-%h.ExAmPlE.CoM");
    assert_int_equal(ssh_options_apply(session), SSH_ERROR);

    /* Hostname %h uses the current host value, not originalhost */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my-alias");
    SAFE_FREE(session->opts.host);
    session->opts.host = strdup("192.0.2.1");
    assert_non_null(session->opts.host);
    assert_string_equal(session->opts.host, "192.0.2.1");
    assert_string_equal(session->opts.originalhost, "my-alias");
    _parse_config(session,
                  NULL,
                  "Host my-alias\n\tHostName %h.example.com\n",
                  SSH_OK);
    assert_string_equal(session->opts.host, "192.0.2.1.example.com");
    assert_string_equal(session->opts.originalhost, "my-alias");
    assert_int_equal(ssh_options_apply(session), SSH_OK);
    assert_string_equal(session->opts.host, "192.0.2.1.example.com");
    assert_string_equal(session->opts.originalhost, "my-alias");

    /* Hostname with unsupported tokens is rejected and unknown percent-escape
     * keys are treated as fatal errors
     */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my-alias");
    _parse_config(session,
                  NULL,
                  "Host my-alias\n\tHostName FoO-%p.ExAmPlE.CoM\n",
                  SSH_ERROR);
    assert_string_equal(session->opts.host, "my-alias");
    assert_string_equal(session->opts.originalhost, "my-alias");
    assert_null(session->opts.config_hostname);

    /* Unsupported uppercase escapes are also rejected. */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my-alias");
    _parse_config(session,
                  NULL,
                  "Host my-alias\n\tHostName FoO-%H.ExAmPlE.CoM\n",
                  SSH_ERROR);
    assert_string_equal(session->opts.host, "my-alias");
    assert_string_equal(session->opts.originalhost, "my-alias");
    assert_null(session->opts.config_hostname);

    /* Hostname rejects incomplete tokens such as a trailing % */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my-alias");
    _parse_config(session,
                  NULL,
                  "Host my-alias\n\tHostName foo-%\n",
                  SSH_ERROR);

    /* Hostname %% is syntactically valid but still must produce a hostname */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my-alias");
    _parse_config(session, NULL, "Host my-alias\n\tHostName %%\n", SSH_OK);
    assert_string_equal(session->opts.host, "%");

    /* Match host sees the resolved HostName during parsing */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my-alias");
    _parse_config(session,
                  NULL,
                  "Host my-alias\n\tHostName %h.example.com\n"
                  "Match host my-alias.example.com\n\tPort 2222\n",
                  SSH_OK);
    assert_int_equal(session->opts.port, 2222);

#ifndef WITH_EXEC
    /* Match exec is not supported on Windows at this moment */
#else
    /* Match exec expands %h from the resolved HostName during parsing */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my-alias");
    _parse_config(session,
                  NULL,
                  "Host my-alias\n\tHostName %h.example.com\n"
                  "Match exec \"test %h = my-alias.example.com\"\n"
                  "\tPort 2200\n",
                  SSH_OK);
    assert_int_equal(session->opts.port, 2200);
#endif

    /* Host keyword compares against originalhost, not the resolved IP */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "ssh-host");
    _parse_config(session,
                  NULL,
                  "Host ssh-host\n\tHostname 10.1.1.1\n"
                  "Host 10.1.1.*\n\tProxyJump ssh-host\n",
                  SSH_OK);
    assert_string_equal(session->opts.host, "10.1.1.1");
    assert_string_equal(session->opts.originalhost, "ssh-host");
    assert_int_equal(ssh_list_count(session->opts.proxy_jumps), 0);
    assert_null(session->opts.ProxyCommand);

    /* %h falls back to originalhost when host is not yet resolved */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my_alias");
    assert_null(session->opts.host);
    expanded = ssh_path_expand_escape(session, "%h");
    assert_non_null(expanded);
    assert_string_equal(expanded, "my_alias");
    free(expanded);

    /* HostName should be lowercased */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "my_host");
    _parse_config(session,
                  NULL,
                  "Host my_host\n\tHostname LOCALHOST\n",
                  SSH_OK);
    assert_string_equal(session->opts.host, "LOCALHOST");
    assert_int_equal(ssh_options_apply(session), SSH_OK);
    assert_string_equal(session->opts.host, "localhost");
}

static void torture_config_boolean_aliases(void **state)
{
    ssh_session session = *state;

    /* Verify true/false/yes/no are accepted and case-insensitive */
    torture_reset_config(session);
    _parse_config(session, NULL, "StrictHostKeyChecking yes\n", SSH_OK);
    assert_int_equal(session->opts.StrictHostKeyChecking, 1);

    torture_reset_config(session);
    _parse_config(session, NULL, "StrictHostKeyChecking no\n", SSH_OK);
    assert_int_equal(session->opts.StrictHostKeyChecking, 0);

    torture_reset_config(session);
    _parse_config(session, NULL, "StrictHostKeyChecking true\n", SSH_OK);
    assert_int_equal(session->opts.StrictHostKeyChecking, 1);

    torture_reset_config(session);
    _parse_config(session, NULL, "StrictHostKeyChecking false\n", SSH_OK);
    assert_int_equal(session->opts.StrictHostKeyChecking, 0);

    torture_reset_config(session);
    _parse_config(session, NULL, "StrictHostKeyChecking TRUE\n", SSH_OK);
    assert_int_equal(session->opts.StrictHostKeyChecking, 1);

    /* Invalid suffix should be ignored and not applied to session */
    torture_reset_config(session);
    _parse_config(session, NULL, "StrictHostKeyChecking yes\n", SSH_OK);
    assert_int_equal(session->opts.StrictHostKeyChecking, 1);

    _parse_config(session, NULL, "StrictHostKeyChecking no_please\n", SSH_OK);
    assert_int_equal(session->opts.StrictHostKeyChecking, 1);
}

static void torture_config_hostname_scan_null(void **state)
{
    ssh_session session = *state;
    int rc;
    bool needs_host = true;

    rc = ssh_config_scan_hostname_tokens(session,
                                         NULL,
                                         &needs_host);
    assert_int_equal(rc, -1);
    assert_false(needs_host);
    assert_string_equal(ssh_get_error(session),
                        "Cannot scan HostName tokens from NULL input");
}

/* Invalid configuration files
 */
static void torture_config_invalid(void **state)
{
    ssh_session session = *state;

    ssh_options_set(session, SSH_OPTIONS_HOST, "Bar");

    /* non-regular file -- ignored (or missing on non-unix) so OK */
    _parse_config(session, "/dev/random", NULL, SSH_OK);

#ifndef _WIN32
    /* huge file -- ignored (or missing on non-unix) so OK */
    _parse_config(session, "/proc/kcore", NULL, SSH_OK);
#endif
}

/* Issue #365: a value set via ssh_options_set() before config parsing must
 * NOT be overridden by the config file. */
static void torture_config_user_not_overridden(void **state)
{
    ssh_session session = *state;
    char *user = NULL;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_USER, "appuser");
    assert_ssh_return_code(session, rc);

    _parse_config(session, NULL, "User configuser\n", SSH_OK);

    rc = ssh_options_get(session, SSH_OPTIONS_USER, &user);
    assert_ssh_return_code(session, rc);
    assert_non_null(user);
    assert_string_equal(user, "appuser");
    SSH_STRING_FREE_CHAR(user);
}

/* When the application did NOT set User, the config value still applies. */
static void torture_config_user_from_config_applies(void **state)
{
    ssh_session session = *state;
    char *user = NULL;
    int rc;

    _parse_config(session, NULL, "User configuser\n", SSH_OK);

    rc = ssh_options_get(session, SSH_OPTIONS_USER, &user);
    assert_ssh_return_code(session, rc);
    assert_non_null(user);
    assert_string_equal(user, "configuser");
    SSH_STRING_FREE_CHAR(user);
}

/* Protection is general, not User-specific: an app-set Port survives config. */
static void torture_config_port_not_overridden(void **state)
{
    ssh_session session = *state;
    unsigned int port = 2020;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    assert_ssh_return_code(session, rc);

    _parse_config(session, NULL, "Port 2222\n", SSH_OK);
    assert_int_equal(session->opts.port, 2020);
}

/* The host match key is NOT protected: config HostName still resolves an
 * app-set alias to the real hostname. */
static void torture_config_hostname_still_resolves(void **state)
{
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "myalias");
    assert_ssh_return_code(session, rc);

    _parse_config(session,
                  NULL,
                  "Host myalias\n\tHostName real.example.com\n",
                  SSH_OK);

    assert_non_null(session->opts.host);
    assert_string_equal(session->opts.host, "real.example.com");
}

/* HostName keeps its own "first obtained value wins" precedence between config
 * entries, independently of the application-set SSH_OPTIONS_HOST lookup key.
 * Every target below resolves to the first HostName, matching OpenSSH:
 *
 *   $ ssh -F config -G test  | grep ^hostname   ->  hostname test
 *   $ ssh -F config -G test2 | grep ^hostname   ->  hostname test
 *   $ ssh -F config -G test3 | grep ^hostname   ->  hostname test
 */
static void torture_config_hostname_first_wins(void **state)
{
    ssh_session session = *state;
    const char *config = "HostName test\n"
                         "HostName test2\n"
                         "Match host test2\n"
                         "\tHostName test3\n";
    const char *targets[] = {"test", "test2", "test3"};
    size_t i;
    int rc;

    (void)session;

    for (i = 0; i < ARRAY_SIZE(targets); i++) {
        ssh_session s = ssh_new();
        assert_non_null(s);

        rc = ssh_options_set(s, SSH_OPTIONS_HOST, targets[i]);
        assert_ssh_return_code(s, rc);

        _parse_config(s, NULL, config, SSH_OK);

        assert_non_null(s->opts.host);
        assert_string_equal(s->opts.host, "test");

        ssh_free(s);
    }
}

/* Operational options like log verbosity are NOT protected: config LogLevel
 * still applies even if the application set verbosity beforehand. */
static void torture_config_loglevel_not_overridden(void **state)
{
    ssh_session session = *state;
    int level = SSH_LOG_NOLOG;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &level);
    assert_ssh_return_code(session, rc);

    _parse_config(session, NULL, "LogLevel DEBUG3\n", SSH_OK);

    assert_int_equal(session->common.log_verbosity, SSH_LOG_TRACE);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_config_include_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_include_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_include_recursive_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_include_recursive_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_double_ports_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_double_ports_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_glob_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_glob_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_new_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_new_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_auth_methods_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_auth_methods_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_numeric_invalid_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_numeric_invalid_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_timeout_suffix_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_timeout_suffix_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_boolean_invalid_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_boolean_invalid_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_boolean_compat_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_boolean_compat_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_unknown_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_unknown_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_match_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_match_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_match_version_negative,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_proxyjump_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_proxyjump_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_control_path_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_control_path_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_control_master_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_control_master_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_batch_mode_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_batch_mode_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_forward_agent_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_forward_agent_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            torture_config_exit_on_forward_failure_file,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            torture_config_exit_on_forward_failure_string,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            torture_config_server_alive_interval_file,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            torture_config_server_alive_interval_string,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            torture_config_server_alive_count_max_file,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            torture_config_server_alive_count_max_string,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            torture_config_preferred_authentications_file,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            torture_config_preferred_authentications_string,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            torture_config_number_of_password_prompts_file,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            torture_config_number_of_password_prompts_string,
            setup,
            teardown),
        cmocka_unit_test_setup_teardown(torture_config_request_tty_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_request_tty_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_escape_char_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_escape_char_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_local_forward_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_local_forward_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_remote_forward_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_remote_forward_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_send_env_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_send_env_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_address_family_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_address_family_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_rekey_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_rekey_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_rekey_cli_optional_time,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_plus_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_plus_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_minus_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_minus_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_caret_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_caret_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_pubkeytypes_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_pubkeytypes_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_pubkeyalgorithms_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_pubkeyalgorithms_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_nonewlineend_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_nonewlineend_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_nonewlineoneline_file,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_nonewlineoneline_string,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_parser_get_cmd,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_parser_get_token,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_parser_get_token_info,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_parser_get_yesno,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_match_pattern,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_identity,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_make_absolute,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_make_absolute_no_sshdir,
                                        setup_no_sshdir,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_parse_uri,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_match_complex,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_loglevel_missing_value,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_jump, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_config_hostname,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_boolean_aliases,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_hostname_scan_null,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_invalid,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_user_not_overridden,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_user_from_config_applies,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_port_not_overridden,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_hostname_still_resolves,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_hostname_first_wins,
                                        setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_config_loglevel_not_overridden,
                                        setup,
                                        teardown),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests,
            setup_config_files, teardown_config_files);
    ssh_finalize();
    return rc;
}
