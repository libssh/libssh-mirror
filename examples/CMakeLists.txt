project(libssh-examples C CXX)

set(examples_SRCS
  authentication.c
  knownhosts.c
  connect_ssh.c
)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
  ${ARGP_INCLUDE_DIR}
  ${CMAKE_BINARY_DIR}
)

if (UNIX AND NOT WIN32)
    add_executable(libssh_scp libssh_scp.c ${examples_SRCS})
    target_link_libraries(libssh_scp ${LIBSSH_SHARED_LIBRARY})

    add_executable(scp_download scp_download.c ${examples_SRCS})
    target_link_libraries(scp_download ${LIBSSH_SHARED_LIBRARY})

    add_executable(sshnetcat sshnetcat.c ${examples_SRCS})
    target_link_libraries(sshnetcat ${LIBSSH_SHARED_LIBRARY})

    if (WITH_SFTP)
        add_executable(samplesftp samplesftp.c ${examples_SRCS})
        target_link_libraries(samplesftp ${LIBSSH_SHARED_LIBRARY})
    endif (WITH_SFTP)

    add_executable(samplessh sample.c ${examples_SRCS})
    target_link_libraries(samplessh ${LIBSSH_SHARED_LIBRARY})

    if (WITH_SERVER)
        if (HAVE_LIBUTIL)
            add_executable(ssh_server_fork ssh_server_fork.c)
            target_link_libraries(ssh_server_fork ${LIBSSH_SHARED_LIBRARY} ${ARGP_LIBRARY} util)
        endif (HAVE_LIBUTIL)

        if (WITH_GSSAPI AND GSSAPI_FOUND)
            add_executable(samplesshd-cb samplesshd-cb.c)
            target_link_libraries(samplesshd-cb ${LIBSSH_SHARED_LIBRARY} ${ARGP_LIBRARY})

            add_executable(proxy proxy.c)
            target_link_libraries(proxy ${LIBSSH_SHARED_LIBRARY} ${ARGP_LIBRARY})
        endif (WITH_GSSAPI AND GSSAPI_FOUND)

        add_executable(samplesshd-kbdint samplesshd-kbdint.c)
        target_link_libraries(samplesshd-kbdint ${LIBSSH_SHARED_LIBRARY} ${ARGP_LIBRARY})

    endif (WITH_SERVER)
endif (UNIX AND NOT WIN32)

add_executable(exec exec.c ${examples_SRCS})
target_link_libraries(exec ${LIBSSH_SHARED_LIBRARY})

add_executable(senddata senddata.c ${examples_SRCS})
target_link_libraries(senddata ${LIBSSH_SHARED_LIBRARY})

add_executable(libsshpp libsshpp.cpp)
target_link_libraries(libsshpp ${LIBSSH_SHARED_LIBRARY})

add_executable(libsshpp_noexcept libsshpp_noexcept.cpp)
target_link_libraries(libsshpp_noexcept ${LIBSSH_SHARED_LIBRARY})
