project(libssh-headers)

set(libssh_HDRS
  libssh.h
  crypto.h
  server.h
  sftp.h
  ssh1.h
  ssh2.h
)

INSTALL(
  FILES
    ${libssh_HDRS}
  DESTINATION
    ${INCLUDE_INSTALL_DIR}/${APPLICATION_NAME}
)

