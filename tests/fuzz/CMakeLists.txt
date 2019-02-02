project(fuzzing CXX)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_executable(ssh_client_fuzzer ssh_client_fuzzer.cpp)
    target_link_libraries(ssh_client_fuzzer
                          PRIVATE
                              ${LIBSSH_STATIC_LIBRARY})
    set_target_properties(ssh_client_fuzzer
                          PROPERTIES
                              COMPILE_FLAGS "-fsanitize=fuzzer"
                              LINK_FLAGS "-fsanitize=fuzzer")


    add_executable(ssh_server_fuzzer ssh_server_fuzzer.cpp)
    target_link_libraries(ssh_server_fuzzer
                          PRIVATE
                              ${LIBSSH_STATIC_LIBRARY})
    set_target_properties(ssh_server_fuzzer
        PROPERTIES
            COMPILE_FLAGS "-fsanitize=fuzzer"
            LINK_FLAGS "-fsanitize=fuzzer")

    # Run the fuzzer to make sure it works
    add_test(ssh_client_fuzzer ${CMAKE_CURRENT_BINARY_DIR}/ssh_client_fuzzer -runs=1)
    add_test(ssh_server_fuzzer ${CMAKE_CURRENT_BINARY_DIR}/ssh_server_fuzzer -runs=1)
endif()
