project(libssh-library)

set(LIBSSH_PUBLIC_INCLUDE_DIRS
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}
  CACHE INTERNAL "libssh public include directories"
)

set(LIBSSH_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${OPENSSL_INCLUDE_DIRS}
  ${GCRYPT_INCLUDE_DIRS}
  ${ZLIB_INCLUDE_DIRS}
)

set(LIBSSH_LIBRARY
  libssh
  CACHE INTERNAL "libssh library"
)

set(LIBSSH_LINK_LIBRARIES
  ${LIBSSH_LIBRARY}
  ${CRYPTO_LIBRARY}
  ${GCRYPT_LIBRARY}
  ${ZLIB_LIBRARIES}
)

set(libssh_SRCS
  agent.c
  auth1.c
  auth.c
  base64.c
  buffer.c
  channels1.c
  channels.c
  client.c
  CMakeLists.txt
  connect.c
  crc32.c
  crypt.c
  dh.c
  error.c
  gcrypt_missing.c
  gzip.c
  init.c
  kex.c
  keyfiles.c
  keys.c
  libssh.vers
  log.c
  Makefile.am
  match.c
  messages.c
  misc.c
  options.c
  packet.c
  server.c
  session.c
  sftp.c
  sftpserver.c
  socket.c
  string.c
  wrapper.c
)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
  ${LIBSSH_PRIVATE_INCLUDE_DIRS}
)

add_library(${LIBSSH_LIBRARY} SHARED ${libssh_SRCS})

target_link_libraries(${LIBSSH_LINK_LIBRARIES})

set_target_properties(
  ${LIBSSH_LIBRARY}
    PROPERTIES
      VERSION
        ${LIBRARY_VERSION}
      SOVERSION
        ${LIBRARY_SOVERSION}
)

install(
  TARGETS
    ${LIBSSH_LIBRARY}
  DESTINATION
    ${LIB_INSTALL_DIR}
)

