#include "config.h"

#define LIBSSH_STATIC

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "torture.h"
#include "torture_key.h"

#include <libssh/libssh.h>

#define TEST_SERVER_HOST  "127.0.0.1"
#define TEST_SERVER_PORT  2222
#define TEST_FORWARD_HOST "127.0.0.1"
#define TEST_FORWARD_PORT 8080

struct hostkey_state {
    const char *hostkey;
    char *hostkey_path;
    enum ssh_keytypes_e key_type;
    int fd;
};

static bool is_server_ready = false;
static pthread_mutex_t server_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t server_cond = PTHREAD_COND_INITIALIZER;

static int setup(void **state)
{
    struct hostkey_state *h = NULL;
    mode_t mask;
    int rc;

    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    rc = ssh_init();
    if (rc != SSH_OK) {
        return -1;
    }

    h = (struct hostkey_state *)malloc(sizeof(struct hostkey_state));
    assert_non_null(h);

    h->hostkey_path = strdup("/tmp/libssh_hostkey_XXXXXX");
    assert_non_null(h->hostkey_path);

    mask = umask(S_IRWXO | S_IRWXG);
    h->fd = mkstemp(h->hostkey_path);
    umask(mask);
    assert_return_code(h->fd, errno);
    close(h->fd);

    h->key_type = SSH_KEYTYPE_ECDSA_P256;
    h->hostkey = torture_get_testkey(h->key_type, 0);

    torture_write_file(h->hostkey_path, h->hostkey);

    *state = h;

    /* Reset before every test */
    is_server_ready = false;

    return 0;
}

static int teardown(void **state)
{
    struct hostkey_state *h = (struct hostkey_state *)*state;

    unlink(h->hostkey_path);
    free(h->hostkey_path);
    free(h);

    ssh_finalize();

    return 0;
}

static int auth_password_accept(ssh_session session,
                                const char *user,
                                const char *password,
                                void *userdata)
{
    /* unused */
    (void)session;
    (void)user;
    (void)password;
    (void)userdata;

    return SSH_AUTH_SUCCESS;
}

struct global_request_data {
    /* Set once the server has handled a global request. */
    int req_seen;
};

/* Registering a callback routes ssh_packet_global_request() to the
 * fall-through path that frees the message; reply success to unblock the
 * client. */
static void global_request_callback(ssh_session session,
                                    ssh_message message,
                                    void *userdata)
{
    struct global_request_data *grq = (struct global_request_data *)userdata;

    (void)session;

    if (ssh_message_type(message) == SSH_REQUEST_GLOBAL) {
        /* The subtype is assigned only after ssh_buffer_unpack() succeeds,
         * so TCPIP_FORWARD means bind_address holds a live heap allocation. */
        assert_int_equal(ssh_message_subtype(message),
                         SSH_GLOBAL_REQUEST_TCPIP_FORWARD);
        assert_string_equal(ssh_message_global_request_address(message),
                            TEST_FORWARD_HOST);
        grq->req_seen = 1;
        ssh_message_global_request_reply_success(message, 0);
    }
}

static void *server_thread(void *arg)
{
    struct hostkey_state *h = (struct hostkey_state *)arg;
    ssh_bind sshbind = NULL;
    ssh_session server = NULL;
    ssh_event event = NULL;
    struct global_request_data grq = {
        .req_seen = 0,
    };
    int rc;

    struct ssh_server_callbacks_struct server_cb = {
        .auth_password_function = auth_password_accept,
    };
    struct ssh_callbacks_struct generic_cb = {
        .userdata = &grq,
        .global_request_function = global_request_callback,
    };

    ssh_callbacks_init(&server_cb);
    ssh_callbacks_init(&generic_cb);

    /* Create server */
    sshbind = torture_ssh_bind(TEST_SERVER_HOST,
                               TEST_SERVER_PORT,
                               h->key_type,
                               h->hostkey_path);
    assert_non_null(sshbind);

    server = ssh_new();
    assert_non_null(server);

    rc = ssh_set_server_callbacks(server, &server_cb);
    assert_int_equal(rc, SSH_OK);

    /* global_request_function is generic, not a server callback. */
    rc = ssh_set_callbacks(server, &generic_cb);
    assert_int_equal(rc, SSH_OK);

    /* Signal that the server is ready */
    pthread_mutex_lock(&server_mutex);
    is_server_ready = true;
    pthread_cond_signal(&server_cond);
    pthread_mutex_unlock(&server_mutex);

    rc = ssh_bind_accept(sshbind, server);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_handle_key_exchange(server);
    assert_int_equal(rc, SSH_OK);

    /* Handle client connection */
    event = ssh_event_new();
    assert_non_null(event);

    rc = ssh_event_add_session(event, server);
    assert_int_equal(rc, SSH_OK);

    /* Poll until the client's "tcpip-forward" request has been handled;
     * auth is driven by the registered callbacks in the same loop. */
    while (grq.req_seen == 0) {
        rc = ssh_event_dopoll(event, -1);
        if (rc == SSH_ERROR) {
            break;
        }
    }

    ssh_event_free(event);
    ssh_bind_free(sshbind);
    ssh_free(server);

    return NULL;
}

static void torture_server_global_request_tcpip_forward(void **state)
{
    struct hostkey_state *h = (struct hostkey_state *)*state;
    pthread_t server_pthread;
    ssh_session session = NULL;
    unsigned int server_port = TEST_SERVER_PORT;
    int rc;

    rc = pthread_create(&server_pthread, NULL, server_thread, h);
    assert_return_code(rc, errno);

    /* Wait for the server to be ready using condition variable */
    pthread_mutex_lock(&server_mutex);
    while (!is_server_ready) {
        pthread_cond_wait(&server_cond, &server_mutex);
    }
    pthread_mutex_unlock(&server_mutex);

    session =
        torture_ssh_session(NULL, "127.0.0.1", &server_port, "foo", "bar");
    assert_non_null(session);

    /* Sends "tcpip-forward"; want_reply = 1 blocks until the server replies. */
    rc = ssh_channel_listen_forward(session,
                                    TEST_FORWARD_HOST,
                                    TEST_FORWARD_PORT,
                                    NULL);
    assert_int_equal(rc, SSH_OK);

    /* Cleanup */
    ssh_free(session);

    rc = pthread_join(server_pthread, NULL);
    assert_int_equal(rc, 0);
}

int torture_run_tests(void)
{
    int rc;
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            torture_server_global_request_tcpip_forward,
            setup,
            teardown),
    };

    rc = cmocka_run_group_tests(tests, NULL, NULL);
    return rc;
}
