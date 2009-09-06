project(libssh-examples C)

set(examples_SRCS
  authentication.c
  knownhosts.c
  connect_ssh.c
)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
)

add_executable(libssh_scp libssh_scp.c ${examples_SRCS})
add_executable(scp_download scp_download.c ${examples_SRCS})

target_link_libraries(libssh_scp ${LIBSSH_SHARED_LIBRARY})
target_link_libraries(scp_download ${LIBSSH_SHARED_LIBRARY})

