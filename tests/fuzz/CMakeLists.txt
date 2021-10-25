project(fuzzing CXX)

macro(fuzzer name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name}
                          PRIVATE
                              ssh::static)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set_target_properties(${name}
                              PROPERTIES
                                  COMPILE_FLAGS "-fsanitize=fuzzer"
                                  LINK_FLAGS "-fsanitize=fuzzer")
        # Run the fuzzer to make sure it works
        add_test(${name} ${CMAKE_CURRENT_BINARY_DIR}/${name} -runs=1)
    else()
        target_sources(${name} PRIVATE fuzzer.c)
        # Run the fuzzer to make sure it works
        # add_test(${name} ${CMAKE_CURRENT_BINARY_DIR}/${name} EXAMPLE)
    endif()
endmacro()

fuzzer(ssh_client_fuzzer)
fuzzer(ssh_server_fuzzer)
fuzzer(ssh_client_config_fuzzer)
