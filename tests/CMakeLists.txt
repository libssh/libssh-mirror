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
target_link_libraries(${TORTURE_LIBRARY} ${CHECK_LIBRARIES} ${LIBSSH_LIBRARY})

set(TEST_TARGET_LIBRARIES ${SUPPORT_LIBRARY})

add_subdirectory(unittests)
