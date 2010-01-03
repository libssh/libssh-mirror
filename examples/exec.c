/* simple exec example */
#include <stdio.h>

#include <libssh/libssh.h>
#include "examples_common.h"

int main(void) {
  ssh_session session;
  ssh_channel channel;
  char buffer[256];
  int rc;

  session = connect_ssh("localhost", NULL, 0);
  if (session == NULL) {
    return 1;
  }

  channel = channel_new(session);;
  if (channel == NULL) {
    ssh_disconnect(session);
    return 1;
  }

  rc = channel_open_session(channel);
  if (rc < 0) {
    channel_close(channel);
    ssh_disconnect(session);
    return 1;
  }

  rc = channel_request_exec(channel, "ps aux");
  if (rc < 0) {
    channel_close(channel);
    ssh_disconnect(session);
    return 1;
  }


  while ((rc = channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
    fwrite(buffer, 1, rc, stdout);
  }
    
  if (rc < 0) {
    channel_close(channel);
    ssh_disconnect(session);
    return 1;
  }

  channel_send_eof(channel);
  channel_close(channel);

  ssh_disconnect(session);

  return 0;
}
