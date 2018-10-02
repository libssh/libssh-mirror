project(clienttests C)

add_cmocka_test(torture_auth torture_auth.c ${TORTURE_LIBRARY})
add_cmocka_test(torture_connect torture_connect.c ${TORTURE_LIBRARY})
add_cmocka_test(torture_session torture_session.c ${TORTURE_LIBRARY})
if (WITH_SFTP)
    add_cmocka_test(torture_sftp_static torture_sftp_static.c ${TORTURE_LIBRARY})
endif (WITH_SFTP)

set(LIBSSH_CLIENT_TESTS
    torture_algorithms
    torture_knownhosts
    torture_request_env
    torture_forward
    torture_proxycommand)

if (WITH_SFTP)
    set(LIBSSH_CLIENT_TESTS
        ${LIBSSH_CLIENT_TESTS}
        torture_sftp_dir
        torture_sftp_read)
endif (WITH_SFTP)

foreach(_CLI_TEST ${LIBSSH_CLIENT_TESTS})
    add_cmocka_test(${_CLI_TEST} ${_CLI_TEST}.c ${TORTURE_LIBRARY})

    if (OSX)
        set_property(
            TEST
                ${_CLI_TEST}
            PROPERTY
            ENVIRONMENT DYLD_FORCE_FLAT_NAMESPACE=1;DYLD_INSERT_LIBRARIES=${SOCKET_WRAPPER_LIBRARY})
    else ()
        set_property(
            TEST
                ${_CLI_TEST}
            PROPERTY
                ENVIRONMENT ${TORTURE_ENVIRONMENT})
    endif()
endforeach()

