project(libssh-headers C)

set(libssh_HDRS
  libssh.h
  crypto.h
  sftp.h
  ssh1.h
  ssh2.h
)

if (WITH_SERVER)
  set(libssh_HDRS
    ${libssh_HDRS}
    server.h
  )
endif (WITH_SERVER)

install(
  FILES
    ${libssh_HDRS}
  DESTINATION
    ${INCLUDE_INSTALL_DIR}/${APPLICATION_NAME}
  COMPONENT
    headers
)

