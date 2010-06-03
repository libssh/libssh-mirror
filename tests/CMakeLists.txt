project(tests C)


set(TORTURE_LIBRARY torture)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
  ${CHECK_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# create test library
add_library(${TORTURE_LIBRARY} SHARED torture.c cmdline.c)
target_link_libraries(${TORTURE_LIBRARY} ${CHECK_LIBRARIES} ${LIBSSH_STATIC_LIBRARY} ${LIBSSH_LINK_LIBRARIES})

set(TEST_TARGET_LIBRARIES ${SUPPORT_LIBRARY} ${LIBSSH_LINK_LIBRARIES})

add_subdirectory(unittests)
if (WITH_CLIENT_TESTING)
    add_subdirectory(client)
endif (WITH_CLIENT_TESTING)
