project(libssh-examples C)

set(examples_SRCS
  libssh_scp.c
  authentication.c
  knownhosts.c
  connect_ssh.c
)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
)

add_executable(libssh_scp ${examples_SRCS})

target_link_libraries(libssh_scp ${LIBSSH_SHARED_LIBRARY})
