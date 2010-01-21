
#include <libssh/libsshpp.hpp>

int main(int argc, const char **argv){
  ssh::Session session;
  session.setOption(SSH_OPTIONS_HOST,"localhost");
  session.connect();
  session.userauthAutopubkey();
  return 0;
}
