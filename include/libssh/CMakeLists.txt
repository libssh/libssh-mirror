project(libssh-headers C)

set(libssh_HDRS
  libssh.h
  crypto.h
  sftp.h
  ssh1.h
  ssh2.h
)

install(
  FILES
    ${libssh_HDRS}
  DESTINATION
    ${INCLUDE_INSTALL_DIR}/${APPLICATION_NAME}
  COMPONENT
    headers
)

if (WITH_SERVER)
  set(server_HDRS
    server.h
  )

  install(
    FILES
      ${server_HDRS}
    DESTINATION
      ${INCLUDE_INSTALL_DIR}/${APPLICATION_NAME}
    COMPONENT
      libraries
  )
endif (WITH_SERVER)

