project(libssh-tests C)

if (BSD OR SOLARIS OR OSX)
    find_package(Argp)
endif (BSD OR SOLARIS OR OSX)

set(TORTURE_LIBRARY torture)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
  ${CMOCKA_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIR}
  ${GCRYPT_INCLUDE_DIR}
  ${ZLIB_INCLUDE_DIR}
  ${CMAKE_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}
)

set(TORTURE_LINK_LIBRARIES
    ${CMOCKA_LIBRARY}
    ${LIBSSH_STATIC_LIBRARY}
    ${LIBSSH_LINK_LIBRARIES})

if (LIBSSH_THREADS)
    set(TORTURE_LINK_LIBRARIES
        ${TORTURE_LINK_LIBRARIES}
        ${LIBSSH_THREADS_STATIC_LIBRARY}
        ${LIBSSH_THREADS_LINK_LIBRARIES})
endif (LIBSSH_THREADS)

# create test library
add_library(${TORTURE_LIBRARY} STATIC cmdline.c torture.c)
target_link_libraries(${TORTURE_LIBRARY}
    ${TORTURE_LINK_LIBRARIES}
    ${ARGP_LIBRARIES}
)

set(TEST_TARGET_LIBRARIES
    ${TORTURE_LIBRARY}
    ${TORTURE_LINK_LIBRARIES}
)

add_subdirectory(unittests)

if (WITH_CLIENT_TESTING)
    find_package(socket_wrapper 1.1.5 REQUIRED)
    find_package(nss_wrapper 1.1.2 REQUIRED)
    find_package(uid_wrapper 1.2.0 REQUIRED)
    find_package(pam_wrapper 1.0.0 REQUIRED)

    find_program(SSHD_EXECUTABLE
                 NAME
                    sshd
                 PATHS
                    /sbin
                    /usr/sbin
                    /usr/local/sbin)
    if (NOT SSHD_EXECUTABLE)
        message(SEND_ERROR "Could not find sshd which is required for client testing")
    endif()

    find_program(SSH_EXECUTABLE NAMES ssh)
    if (SSH_EXECUTABLE)
        execute_process(COMMAND ${SSH_EXECUTABLE} -V ERROR_VARIABLE OPENSSH_VERSION_STR)
        string(REGEX REPLACE "^OpenSSH_([0-9]).[0-9].*$" "\\1" OPENSSH_VERSION_MAJOR "${OPENSSH_VERSION_STR}")
        string(REGEX REPLACE "^OpenSSH_[0-9].([0-9]).*$" "\\1" OPENSSH_VERSION_MINOR "${OPENSSH_VERSION_STR}")
        add_definitions(-DOPENSSH_VERSION_MAJOR=${OPENSSH_VERSION_MAJOR} -DOPENSSH_VERSION_MINOR=${OPENSSH_VERSION_MINOR})
    endif()

    # chroot_wrapper
    add_library(chroot_wrapper SHARED chroot_wrapper.c)
    set(CHROOT_WRAPPER_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}chroot_wrapper${CMAKE_SHARED_LIBRARY_SUFFIX})
    set(TEST_TARGET_LIBRARIES
        ${TEST_TARGET_LIBRARIES}
        chroot_wrapper
    )

    # homedir will be used in passwd
    set(HOMEDIR ${CMAKE_CURRENT_BINARY_DIR}/home)

    ### Setup nss_wrapper
    configure_file(etc/passwd.in ${CMAKE_CURRENT_BINARY_DIR}/etc/passwd @ONLY)
    configure_file(etc/shadow.in ${CMAKE_CURRENT_BINARY_DIR}/etc/shadow @ONLY)
    configure_file(etc/group.in ${CMAKE_CURRENT_BINARY_DIR}/etc/group @ONLY)
    configure_file(etc/hosts.in ${CMAKE_CURRENT_BINARY_DIR}/etc/hosts @ONLY)

    ### Setup pam_wrapper
    configure_file(etc/pam_matrix_passdb.in ${CMAKE_CURRENT_BINARY_DIR}/etc/pam_matrix_passdb @ONLY)
    configure_file(etc/pam.d/sshd.in ${CMAKE_CURRENT_BINARY_DIR}/etc/pam.d/sshd @ONLY)


    set(TORTURE_ENVIRONMENT "LD_PRELOAD=${SOCKET_WRAPPER_LIBRARY}:${NSS_WRAPPER_LIBRARY}:${UID_WRAPPER_LIBRARY}:${PAM_WRAPPER_LIBRARY}:${CHROOT_WRAPPER_LIBRARY}")
    list(APPEND TORTURE_ENVIRONMENT UID_WRAPPER=1 UID_WRAPPER_ROOT=1)
    list(APPEND TORTURE_ENVIRONMENT NSS_WRAPPER_PASSWD=${CMAKE_CURRENT_BINARY_DIR}/etc/passwd)
    list(APPEND TORTURE_ENVIRONMENT NSS_WRAPPER_SHADOW=${CMAKE_CURRENT_BINARY_DIR}/etc/shadow)
    list(APPEND TORTURE_ENVIRONMENT NSS_WRAPPER_GROUP=${CMAKE_CURRENT_BINARY_DIR}/etc/group)
    list(APPEND TORTURE_ENVIRONMENT PAM_WRAPPER_SERVICE_DIR=${CMAKE_CURRENT_BINARY_DIR}/etc/pam.d)

    # Give bob some keys
    file(COPY keys/id_rsa DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rsa.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)

    # Allow to auth with bob his public keys on alice account
    configure_file(keys/id_rsa.pub ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys @ONLY)

    message(STATUS "TORTURE_ENVIRONMENT=${TORTURE_ENVIRONMENT}")

    add_subdirectory(client)
endif (WITH_CLIENT_TESTING)

if (WITH_BENCHMARKS)
    add_subdirectory(benchmarks)
endif (WITH_BENCHMARKS)

if (WITH_SERVER)
    add_subdirectory(pkd)
endif (WITH_SERVER)
