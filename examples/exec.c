/* simple exec example */
#include <stdio.h>

#include <libssh/libssh.h>
#include "examples_common.h"

int main(void) {
  ssh_session session;
  ssh_channel channel;
  ssh_buffer buf;
  int rc;

  session = connect_ssh("localhost", NULL, 0);
  if (session == NULL) {
    return 1;
  }

  channel = channel_new(session);;
  if (channel == NULL) {
    ssh_disconnect(session);
    ssh_finalize();
    return 1;
  }

  rc = channel_open_session(channel);
  if (rc < 0) {
    channel_close(channel);
    ssh_disconnect(session);
    ssh_finalize();
    return 1;
  }

  rc = channel_request_exec(channel, "ps aux");
  if (rc < 0) {
    channel_close(channel);
    ssh_disconnect(session);
    ssh_finalize();
    return 1;
  }


  if (channel_is_open(channel)) {
    while (channel_poll(channel, 0) >= 0) {
      buf = buffer_new();
      rc = channel_read_buffer(channel, buf, 0, 0);
      if (rc < 0) {
        buffer_free(buf);
        channel_close(channel);
        ssh_disconnect(session);
        ssh_finalize();
        return 1;
      }

      printf("%s\n", (char *) buffer_get(buf));

      buffer_free(buf);
    }
  }

  channel_send_eof(channel);
  channel_close(channel);

  ssh_disconnect(session);
  ssh_finalize();

  return 0;
}
