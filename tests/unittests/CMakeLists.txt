project(unittests C)

include_directories(${OPENSSL_INCLUDE_DIR})

add_cmocka_test(torture_buffer torture_buffer.c ${TEST_TARGET_LIBRARIES})
target_compile_options(torture_buffer PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

add_cmocka_test(torture_callbacks torture_callbacks.c ${TEST_TARGET_LIBRARIES})
target_compile_options(torture_callbacks PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

add_cmocka_test(torture_crypto torture_crypto.c ${TEST_TARGET_LIBRARIES})
target_compile_options(torture_crypto PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

add_cmocka_test(torture_init torture_init.c ${TEST_TARGET_LIBRARIES})
target_compile_options(torture_init PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

add_cmocka_test(torture_list torture_list.c ${TEST_TARGET_LIBRARIES})
target_compile_options(torture_list PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

add_cmocka_test(torture_misc torture_misc.c ${TEST_TARGET_LIBRARIES})
target_compile_options(torture_misc PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

add_cmocka_test(torture_config torture_config.c ${TEST_TARGET_LIBRARIES})
target_compile_options(torture_config PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

add_cmocka_test(torture_options torture_options.c ${TEST_TARGET_LIBRARIES})
target_compile_options(torture_options PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

add_cmocka_test(torture_isipaddr torture_isipaddr.c ${TEST_TARGET_LIBRARIES})
target_compile_options(torture_isipaddr PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

add_cmocka_test(torture_knownhosts_parsing torture_knownhosts_parsing.c ${TEST_TARGET_LIBRARIES})
target_compile_options(torture_knownhosts_parsing PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

add_cmocka_test(torture_hashes torture_hashes.c ${TEST_TARGET_LIBRARIES})
target_compile_options(torture_hashes PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

if (CMAKE_USE_PTHREADS_INIT)
    add_cmocka_test(torture_rand torture_rand.c ${TEST_TARGET_LIBRARIES})
    target_compile_options(torture_rand PRIVATE ${DEFAULT_C_COMPILE_FLAGS})
    target_link_libraries(torture_rand Threads::Threads)

    add_cmocka_test(torture_threads_init torture_threads_init.c ${TEST_TARGET_LIBRARIES})
    target_compile_options(torture_threads_init PRIVATE ${DEFAULT_C_COMPILE_FLAGS})
    target_link_libraries(torture_threads_init Threads::Threads)

    add_cmocka_test(torture_threads_buffer torture_threads_buffer.c ${TEST_TARGET_LIBRARIES})
    target_compile_options(torture_threads_buffer PRIVATE ${DEFAULT_C_COMPILE_FLAGS})
    target_link_libraries(torture_threads_buffer Threads::Threads)

    add_cmocka_test(torture_threads_crypto torture_threads_crypto.c ${TEST_TARGET_LIBRARIES})
    target_compile_options(torture_threads_crypto PRIVATE ${DEFAULT_C_COMPILE_FLAGS})
    target_link_libraries(torture_threads_crypto Threads::Threads)
endif ()

if (UNIX AND NOT WIN32)
    # this uses a socketpair
    add_cmocka_test(torture_packet torture_packet.c ${TEST_TARGET_LIBRARIES})
    target_compile_options(torture_packet PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

    # requires ssh-keygen
    add_cmocka_test(torture_keyfiles torture_keyfiles.c ${TEST_TARGET_LIBRARIES})

    add_cmocka_test(torture_pki torture_pki.c ${TEST_TARGET_LIBRARIES})
    target_compile_options(torture_pki PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

    add_cmocka_test(torture_pki_rsa torture_pki_rsa.c ${TEST_TARGET_LIBRARIES})
    target_compile_options(torture_pki_rsa PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

    add_cmocka_test(torture_pki_ed25519 torture_pki_ed25519.c ${TEST_TARGET_LIBRARIES})
    target_compile_options(torture_pki_ed25519 PRIVATE ${DEFAULT_C_COMPILE_FLAGS})

    if (HAVE_DSA)
        add_cmocka_test(torture_pki_dsa torture_pki_dsa.c ${TEST_TARGET_LIBRARIES})
        target_compile_options(torture_pki_dsa PRIVATE ${DEFAULT_C_COMPILE_FLAGS})
    endif()
    if (HAVE_ECC)
        add_cmocka_test(torture_pki_ecdsa torture_pki_ecdsa.c ${TEST_TARGET_LIBRARIES})
        target_compile_options(torture_pki_ecdsa PRIVATE ${DEFAULT_C_COMPILE_FLAGS})
    endif()

    # requires /dev/null
    add_cmocka_test(torture_channel torture_channel.c ${TEST_TARGET_LIBRARIES})
    target_compile_options(torture_channel PRIVATE ${DEFAULT_C_COMPILE_FLAGS})
    # requires pthread
    if (CMAKE_USE_PTHREADS_INIT)
        add_cmocka_test(torture_threads_pki_rsa torture_threads_pki_rsa.c ${TEST_TARGET_LIBRARIES})
        target_compile_options(torture_threads_pki_rsa PRIVATE ${DEFAULT_C_COMPILE_FLAGS})
        target_link_libraries(torture_threads_pki_rsa Threads::Threads)

        # Not working correctly
        #if (WITH_SERVER)
        #    add_cmocka_test(torture_server_x11 torture_server_x11.c ${TEST_TARGET_LIBRARIES})
        #endif (WITH_SERVER)
    endif ()
endif (UNIX AND NOT WIN32)
