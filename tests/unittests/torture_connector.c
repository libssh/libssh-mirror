#include "config.h"

#define LIBSSH_STATIC
#include "libssh/buffer.h"
#include "libssh/channels.h"
#include "libssh/misc.h"
#include "libssh/packet.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/socket.h"
#include "libssh/ssh2.h"
#include "torture.h"

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "connector.c"

struct connector_state {
    ssh_session session;
    ssh_channel channel;
    ssh_connector connector;
    struct ssh_channel_callbacks_struct callbacks;
    unsigned int writable_count;
    int input[2];
    int transport[2];
};

static const char payload[] = "pending input";

static int record_writable(ssh_session session,
                           ssh_channel channel,
                           uint32_t bytes,
                           void *userdata)
{
    struct connector_state *s = userdata;

    (void)session;
    (void)channel;
    assert_true(bytes > 0);
    s->writable_count++;
    return 0;
}

static int setup_connector(void **state)
{
    struct connector_state *s = NULL;
    int rc;

    s = calloc(1, sizeof(*s));
    assert_non_null(s);
    *state = s;

    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, s->input);
    assert_int_equal(rc, 0);
    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, s->transport);
    assert_int_equal(rc, 0);

    s->session = ssh_new();
    assert_non_null(s->session);
    rc = ssh_socket_set_fd(s->session->socket, s->transport[0]);
    assert_int_equal(rc, SSH_OK);
    ssh_socket_set_connected(s->session->socket, NULL);
    ssh_socket_set_write_wontblock(s->session->socket);
    ssh_set_blocking(s->session, 0);
    s->session->alive = 1;
    s->session->session_state = SSH_SESSION_STATE_AUTHENTICATED;
    s->session->flags |= SSH_SESSION_FLAG_AUTHENTICATED;
    s->session->dh_handshake_state = DH_STATE_FINISHED;

    s->channel = ssh_channel_new(s->session);
    assert_non_null(s->channel);
    s->channel->state = SSH_CHANNEL_STATE_OPEN;
    s->channel->remote_window = 0;
    s->channel->remote_maxpacket = 32768;

    /* Observe notifications before the connector can consume the window. */
    s->callbacks.userdata = s;
    s->callbacks.channel_write_wontblock_function = record_writable;
    ssh_callbacks_init(&s->callbacks);
    rc = ssh_add_channel_callbacks(s->channel, &s->callbacks);
    assert_int_equal(rc, SSH_OK);

    s->connector = ssh_connector_new(s->session);
    assert_non_null(s->connector);
    ssh_connector_set_in_fd(s->connector, s->input[0]);
    rc = ssh_connector_set_out_channel(s->connector,
                                       s->channel,
                                       SSH_CONNECTOR_STDOUT);
    assert_int_equal(rc, SSH_OK);
    s->connector->in_poll =
        ssh_poll_new(s->input[0], POLLIN, ssh_connector_fd_cb, s->connector);
    assert_non_null(s->connector->in_poll);
    ssh_packet_register_socket_callback(s->session, s->session->socket);

    return 0;
}

static int teardown_connector(void **state)
{
    struct connector_state *s = NULL;

    s = *state;
    ssh_connector_free(s->connector);
    ssh_channel_free(s->channel);
    ssh_free(s->session);
    close(s->input[0]);
    close(s->input[1]);
    close(s->transport[1]);
    free(s);

    return 0;
}

static void read_socket_bytes(int fd, unsigned char *buffer, size_t count)
{
    struct ssh_timestamp start;
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    size_t received = 0;
    ssize_t n;
    int timeout;
    int rc;

    /* Use one deadline for the whole read, including interrupted calls. */
    ssh_timestamp_init(&start);
    while (received < count) {
        timeout = ssh_timeout_update(&start, 1000);
        assert_true(timeout > 0);
        rc = poll(&pfd, 1, timeout);
        if (rc < 0 && errno == EINTR) {
            continue;
        }
        assert_int_equal(rc, 1);

        n = recv(fd, buffer + received, count - received, MSG_DONTWAIT);
        if (n < 0 &&
            (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        assert_true(n > 0);
        received += (size_t)n;
    }
}

static void notify_writable(struct connector_state *s)
{
    s->session->socket_callbacks.controlflow(SSH_SOCKET_FLOW_WRITEWONTBLOCK,
                                             s->session);
}

static void queue_input(struct connector_state *s)
{
    ssize_t n;
    int rc;

    n = write(s->input[1], payload, sizeof(payload));
    assert_int_equal(n, sizeof(payload));
    rc = ssh_connector_fd_cb(s->connector->in_poll,
                             s->input[0],
                             POLLIN,
                             s->connector);
    assert_int_equal(rc, 0);
}

static void verify_pending(struct connector_state *s)
{
    char pending;
    ssize_t n;

    assert_false(s->channel->local_eof);
    assert_true(s->connector->in_available);
    assert_false(s->connector->out_wontblock);
    if (s->input[0] < 0) {
        fail_msg("Fixture input fd is invalid");
    }
    n = recv(s->input[0], &pending, sizeof(pending), MSG_PEEK | MSG_DONTWAIT);
    assert_int_equal(n, sizeof(pending));
    assert_int_equal(pending, payload[0]);
}

static void read_data_packet(struct connector_state *s,
                             const char *expected,
                             size_t expected_size)
{
    unsigned char packet[256];
    uint32_t size;
    uint32_t data_size;

    /* Drain the entire unencrypted packet, including its padding. */
    read_socket_bytes(s->transport[1], packet, 4);
    size = ((uint32_t)packet[0] << 24) | ((uint32_t)packet[1] << 16) |
           ((uint32_t)packet[2] << 8) | packet[3];
    assert_true(size >= 10 + expected_size);
    if (size > sizeof(packet) - 4) {
        fail_msg("SSH packet does not fit in test buffer");
        return;
    }
    read_socket_bytes(s->transport[1], packet + 4, size);
    assert_int_equal(packet[5], SSH2_MSG_CHANNEL_DATA);
    data_size = ((uint32_t)packet[10] << 24) | ((uint32_t)packet[11] << 16) |
                ((uint32_t)packet[12] << 8) | packet[13];
    assert_int_equal(data_size, expected_size);
    assert_memory_equal(packet + 14, expected, expected_size);
}

static void recover_window(struct connector_state *s)
{
    ssh_buffer update = NULL;
    int rc;

    update = ssh_buffer_new();
    assert_non_null(update);
    rc = ssh_buffer_pack(update,
                         "dd",
                         s->channel->local_channel,
                         (uint32_t)sizeof(payload));
    assert_int_equal(rc, SSH_OK);
    rc = channel_rcv_change_window(s->session,
                                   SSH2_MSG_CHANNEL_WINDOW_ADJUST,
                                   update,
                                   NULL);
    ssh_buffer_free(update);
    assert_int_equal(rc, SSH_PACKET_USED);
    assert_false(s->channel->local_eof);
    assert_int_equal(s->channel->remote_window, 0);
    read_data_packet(s, payload, sizeof(payload));
}

static void torture_connector_fd_zero_window(void **state)
{
    struct connector_state *s = *state;

    queue_input(s);
    /* A writable transport does not imply a nonempty channel window. */
    notify_writable(s);
    notify_writable(s);
    assert_int_equal(s->writable_count, 0);
    verify_pending(s);
    recover_window(s);
    assert_int_equal(s->writable_count, 1);
}

static void torture_connector_zero_window_before_input(void **state)
{
    struct connector_state *s = *state;

    notify_writable(s);
    assert_int_equal(s->writable_count, 0);
    queue_input(s);
    verify_pending(s);
    recover_window(s);
}

static void torture_connector_window_recovery(void **state)
{
    struct connector_state *s = *state;

    queue_input(s);
    recover_window(s);
    queue_input(s);
    notify_writable(s);
    assert_int_equal(s->writable_count, 1);
    verify_pending(s);
    recover_window(s);
    assert_int_equal(s->writable_count, 2);
}

static void torture_connector_shared_channel(void **state)
{
    struct connector_state *s = *state;
    const char external[] = "external write";
    int rc;

    s->channel->remote_window = sizeof(external);
    notify_writable(s);
    assert_true(s->connector->out_wontblock);

    /* Another writer can exhaust the window after readiness is cached. */
    rc = ssh_channel_write(s->channel, external, sizeof(external));
    assert_int_equal(rc, sizeof(external));
    assert_int_equal(s->channel->remote_window, 0);
    read_data_packet(s, external, sizeof(external));

    notify_writable(s);
    assert_int_equal(s->writable_count, 1);
    queue_input(s);
    verify_pending(s);
    recover_window(s);
}

int torture_run_tests(void)
{
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_connector_fd_zero_window,
                                        setup_connector,
                                        teardown_connector),
        cmocka_unit_test_setup_teardown(
            torture_connector_zero_window_before_input,
            setup_connector,
            teardown_connector),
        cmocka_unit_test_setup_teardown(torture_connector_window_recovery,
                                        setup_connector,
                                        teardown_connector),
        cmocka_unit_test_setup_teardown(torture_connector_shared_channel,
                                        setup_connector,
                                        teardown_connector),
    };
    int rc;

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}
