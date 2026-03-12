project(fuzzing CXX)

# Build SSH server mock helper as object library
add_library(ssh_server_mock_obj OBJECT ssh_server_mock.c)
target_link_libraries(ssh_server_mock_obj PRIVATE ${TORTURE_LINK_LIBRARIES})
if (WITH_COVERAGE)
    append_coverage_compiler_flags_to_target(ssh_server_mock_obj)
endif (WITH_COVERAGE)

macro(fuzzer name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE ${TORTURE_LINK_LIBRARIES})

    # Add ssh_server_mock dependency for scp and sftp fuzzers
    if (${name} STREQUAL "ssh_scp_fuzzer" OR ${name} STREQUAL "ssh_sftp_fuzzer")
        target_sources(${name} PRIVATE $<TARGET_OBJECTS:ssh_server_mock_obj>)
        target_link_libraries(${name} PRIVATE pthread)
    endif()
    if (WITH_COVERAGE)
        append_coverage_compiler_flags_to_target(${name})
    endif (WITH_COVERAGE)

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set_target_properties(${name}
                              PROPERTIES
                                  COMPILE_FLAGS "-fsanitize=fuzzer"
                                  LINK_FLAGS "-fsanitize=fuzzer")
        # Pick up <name>.dict if present
        if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${name}.dict")
            set(_DICT_ARG "-dict=${CMAKE_CURRENT_SOURCE_DIR}/${name}.dict")
        else()
            set(_DICT_ARG "")
        endif()
        # Run the fuzzer to make sure it works
        add_test(${name} ${CMAKE_CURRENT_BINARY_DIR}/${name} ${_DICT_ARG} -runs=1)
        # Run the fuzzer with nalloc to make sure it works
        add_test(${name}_nalloc ${CMAKE_CURRENT_BINARY_DIR}/${name} ${_DICT_ARG} -runs=1)
        set_property(TEST ${name}_nalloc PROPERTY ENVIRONMENT NALLOC_FREQ 32)
    else()
        target_sources(${name} PRIVATE fuzzer.c)
        # Run the fuzzer to make sure it works
        if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${name}_corpus")
            file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/${name}_corpus/*")
            set(i 0)
            foreach(file ${files})
                add_test(${name}_${i}
                         ${CMAKE_CURRENT_BINARY_DIR}/${name} ${file})
                math(EXPR i "${i} + 1")
            endforeach()
        endif()
    endif()
endmacro()

fuzzer(ssh_client_fuzzer)
fuzzer(ssh_client_config_fuzzer)
fuzzer(ssh_known_hosts_fuzzer)
fuzzer(ssh_privkey_fuzzer)
fuzzer(ssh_pubkey_fuzzer)
fuzzer(ssh_sftp_attr_fuzzer)
fuzzer(ssh_sshsig_fuzzer)
fuzzer(ssh_config_diff_fuzzer)
if (WITH_SERVER)
    if (WITH_SCP)
        fuzzer(ssh_scp_fuzzer)
    endif (WITH_SCP)
    fuzzer(ssh_server_fuzzer)
    fuzzer(ssh_bind_config_fuzzer)
endif (WITH_SERVER)
