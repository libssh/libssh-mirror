set(LIBSSH_PUBLIC_INCLUDE_DIRS
  ${libssh_SOURCE_DIR}/include
  CACHE INTERNAL "libssh public include directories"
)

set(LIBSSH_PRIVATE_INCLUDE_DIRS
  ${libssh_BINARY_DIR}
)

set(LIBSSH_LINK_LIBRARIES
  ${LIBSSH_REQUIRED_LIBRARIES}
)

if (WIN32)
  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ws2_32
  )
endif (WIN32)

if (HAVE_LIBSOCKET)
  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    socket
  )
endif (HAVE_LIBSOCKET)

if (OPENSSL_CRYPTO_LIBRARY)
  set(LIBSSH_PRIVATE_INCLUDE_DIRS
    ${LIBSSH_PRIVATE_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
  )

  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ${OPENSSL_CRYPTO_LIBRARY}
  )
endif (OPENSSL_CRYPTO_LIBRARY)

if (MBEDTLS_CRYPTO_LIBRARY)
    set(LIBSSH_PRIVATE_INCLUDE_DIRS
      ${LIBSSH_PRIVATE_INCLUDE_DIRS}
      ${MBEDTLS_INCLUDE_DIR}
    )
  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ${MBEDTLS_CRYPTO_LIBRARY}
  )
endif (MBEDTLS_CRYPTO_LIBRARY)

if (GCRYPT_LIBRARIES)
  set(LIBSSH_PRIVATE_INCLUDE_DIRS
    ${LIBSSH_PRIVATE_INCLUDE_DIRS}
    ${GCRYPT_INCLUDE_DIR}
  )

  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ${GCRYPT_LIBRARIES})
endif()

if (WITH_ZLIB)
  set(LIBSSH_PRIVATE_INCLUDE_DIRS
    ${LIBSSH_PRIVATE_INCLUDE_DIRS}
    ${ZLIB_INCLUDE_DIR}
  )

  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ${ZLIB_LIBRARY}
  )
endif (WITH_ZLIB)

if (WITH_GSSAPI AND GSSAPI_FOUND)
  set(LIBSSH_PRIVATE_INCLUDE_DIRS
    ${LIBSSH_PRIVATE_INCLUDE_DIRS}
    ${GSSAPI_INCLUDE_DIR}
  )

  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ${GSSAPI_LIBRARIES}
  )
endif (WITH_GSSAPI AND GSSAPI_FOUND)

if (WITH_NACL AND NACL_FOUND)
  set(LIBSSH_PRIVATE_INCLUDE_DIRS
    ${LIBSSH_PRIVATE_INCLUDE_DIRS}
    ${NACL_INCLUDE_DIR}
  )

  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ${NACL_LIBRARY}
  )
endif (WITH_NACL AND NACL_FOUND)

set(LIBSSH_LINK_LIBRARIES
  ${LIBSSH_LINK_LIBRARIES}
  CACHE INTERNAL "libssh link libraries"
)

set(LIBSSH_SHARED_LIBRARY
  ssh_shared
  CACHE INTERNAL "libssh shared library"
)

if (BUILD_STATIC_LIB)
  set(LIBSSH_STATIC_LIBRARY
    ssh_static
    CACHE INTERNAL "libssh static library"
  )
endif (BUILD_STATIC_LIB)

set(libssh_SRCS
  agent.c
  auth.c
  base64.c
  bignum.c
  buffer.c
  callbacks.c
  channels.c
  client.c
  config.c
  connect.c
  connector.c
  curve25519.c
  dh.c
  ecdh.c
  error.c
  getpass.c
  init.c
  kex.c
  known_hosts.c
  knownhosts.c
  legacy.c
  log.c
  match.c
  messages.c
  misc.c
  options.c
  packet.c
  packet_cb.c
  packet_crypt.c
  pcap.c
  pki.c
  pki_container_openssh.c
  pki_ed25519.c
  poll.c
  session.c
  scp.c
  socket.c
  string.c
  threads.c
  wrapper.c
  external/bcrypt_pbkdf.c
  external/blowfish.c
  external/chacha.c
  external/ed25519.c
  external/fe25519.c
  external/ge25519.c
  external/poly1305.c
  external/sc25519.c
  chachapoly.c
)

if (DEFAULT_C_NO_DEPRECATION_FLAGS)
    set_source_files_properties(known_hosts.c
                                PROPERTIES
                                    COMPILE_FLAGS ${DEFAULT_C_NO_DEPRECATION_FLAGS})
endif()

if (CMAKE_USE_PTHREADS_INIT)
    set(libssh_SRCS
        ${libssh_SRCS}
        threads/noop.c
        threads/pthread.c
    )
elseif (CMAKE_USE_WIN32_THREADS_INIT)
        set(libssh_SRCS
            ${libssh_SRCS}
            threads/noop.c
            threads/winlocks.c
        )
else()
    set(libssh_SRCS
        ${libssh_SRCS}
        threads/noop.c
    )
endif()

if (WITH_GCRYPT)
    set(libssh_SRCS
        ${libssh_SRCS}
        threads/libgcrypt.c
        libgcrypt.c
        gcrypt_missing.c
        pki_gcrypt.c
        ecdh_gcrypt.c
       )
elseif (WITH_MBEDTLS)
    set(libssh_SRCS
        ${libssh_SRCS}
        threads/mbedtls.c
        libmbedcrypto.c
        mbedcrypto_missing.c
        pki_mbedcrypto.c
        ecdh_mbedcrypto.c
       )
else (WITH_GCRYPT)
    set(libssh_SRCS
        ${libssh_SRCS}
        threads/libcrypto.c
        pki_crypto.c
        ecdh_crypto.c
        libcrypto.c
       )
    if(OPENSSL_VERSION VERSION_LESS "1.1.0")
        set(libssh_SRCS ${libssh_SRCS} libcrypto-compat.c)
    endif()
endif (WITH_GCRYPT)

if (WITH_SFTP)
  set(libssh_SRCS
    ${libssh_SRCS}
    sftp.c
  )

  if (WITH_SERVER)
    set(libssh_SRCS
      ${libssh_SRCS}
      sftpserver.c
    )
  endif (WITH_SERVER)
endif (WITH_SFTP)

if (WITH_SERVER)
  set(libssh_SRCS
    ${libssh_SRCS}
    server.c
    bind.c
  )
endif (WITH_SERVER)

if (WITH_GEX)
  set(libssh_SRCS
    ${libssh_SRCS}
    dh-gex.c
  )
endif (WITH_GEX)

if (WITH_ZLIB)
  set(libssh_SRCS
    ${libssh_SRCS}
    gzip.c
  )
endif(WITH_ZLIB)

if (WITH_GSSAPI AND GSSAPI_FOUND)
  set(libssh_SRCS
    ${libssh_SRCS}
    gssapi.c
  )
endif (WITH_GSSAPI AND GSSAPI_FOUND)

if (NOT WITH_NACL)
  set(libssh_SRCS
    ${libssh_SRCS}
    external/curve25519_ref.c
  )
endif (NOT WITH_NACL)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
  ${LIBSSH_PRIVATE_INCLUDE_DIRS}
)

# Set the path to the default map file
set(MAP_PATH "${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.map")

if (WITH_SYMBOL_VERSIONING AND HAVE_LD_VERSION_SCRIPT AND ABIMAP_FOUND)
    # Get the list of header files
    get_file_list(dev_header_list
                  DIRECTORIES "${LIBSSH_PUBLIC_INCLUDE_DIRS}/libssh"
                  FILES_PATTERNS "*.h")

    # Extract the symbols marked as "LIBSSH_API" from the header files
    extract_symbols("${PROJECT_NAME}_dev.symbols"
                    HEADERS_LIST dev_header_list
                    FILTER_PATTERN "LIBSSH_API")

    if (WITH_ABI_BREAK)
        set(ALLOW_ABI_BREAK "BREAK_ABI")
    endif()

    # Generate the symbol version map file
    generate_map_file("${PROJECT_NAME}_dev.map"
                      SYMBOLS "${PROJECT_NAME}_dev.symbols"
                      RELEASE_NAME_VERSION ${PROJECT_NAME}_AFTER_${LIBRARY_VERSION}
                      CURRENT_MAP ${MAP_PATH}
                      ${ALLOW_ABI_BREAK})

    set(libssh_SRCS
      ${libssh_SRCS}
      ${PROJECT_NAME}_dev.map
    )
endif (WITH_SYMBOL_VERSIONING AND HAVE_LD_VERSION_SCRIPT AND ABIMAP_FOUND)

add_library(${LIBSSH_SHARED_LIBRARY} SHARED ${libssh_SRCS})
target_compile_options(${LIBSSH_SHARED_LIBRARY}
                       PRIVATE
                           ${DEFAULT_C_COMPILE_FLAGS}
                           -D_GNU_SOURCE)

target_link_libraries(${LIBSSH_SHARED_LIBRARY} ${LIBSSH_LINK_LIBRARIES})

if (WITH_SYMBOL_VERSIONING AND HAVE_LD_VERSION_SCRIPT)
    if (ABIMAP_FOUND)
        # Change path to devel map file
        set(MAP_PATH "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}_dev.map")
    endif (ABIMAP_FOUND)

    set_target_properties(${LIBSSH_SHARED_LIBRARY}
                          PROPERTIES LINK_FLAGS
                          "-Wl,--version-script,\"${MAP_PATH}\"")
endif (WITH_SYMBOL_VERSIONING AND HAVE_LD_VERSION_SCRIPT)

set_target_properties(
  ${LIBSSH_SHARED_LIBRARY}
    PROPERTIES
      VERSION
        ${LIBRARY_VERSION}
      SOVERSION
        ${LIBRARY_SOVERSION}
      OUTPUT_NAME
        ssh
      DEFINE_SYMBOL
        LIBSSH_EXPORTS
)

if (WITH_VISIBILITY_HIDDEN)
  set_target_properties(${LIBSSH_SHARED_LIBRARY} PROPERTIES COMPILE_FLAGS "-fvisibility=hidden")
endif (WITH_VISIBILITY_HIDDEN)

if (MINGW)
    set_target_properties(${LIBSSH_SHARED_LIBRARY} PROPERTIES LINK_FLAGS "-Wl,--enable-stdcall-fixup")
endif ()


install(
  TARGETS
    ${LIBSSH_SHARED_LIBRARY}
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
  COMPONENT libraries
)

if (BUILD_STATIC_LIB)
  add_library(${LIBSSH_STATIC_LIBRARY} STATIC ${libssh_SRCS})
  target_compile_options(${LIBSSH_STATIC_LIBRARY}
                         PRIVATE
                            ${DEFAULT_C_COMPILE_FLAGS}
                            -D_GNU_SOURCE)

  if (MSVC)
    set(OUTPUT_SUFFIX static)
  else (MSVC)
    set(OUTPUT_SUFFIX )
  endif (MSVC)
  set_target_properties(
    ${LIBSSH_STATIC_LIBRARY}
      PROPERTIES
        VERSION
          ${LIBRARY_VERSION}
        SOVERSION
          ${LIBRARY_SOVERSION}
        OUTPUT_NAME
          ssh
        ARCHIVE_OUTPUT_DIRECTORY
          ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_SUFFIX}
  )

  if (WIN32)
    set_target_properties(
      ${LIBSSH_STATIC_LIBRARY}
        PROPERTIES
          COMPILE_FLAGS
            "-DLIBSSH_STATIC"
    )
  endif (WIN32)

    if (WITH_STATIC_LIB)
      install(TARGETS
                ${LIBSSH_STATIC_LIBRARY}
              DESTINATION
                ${LIB_INSTALL_DIR}/${OUTPUT_SUFFIX}
              COMPONENT
                libraries)
    endif (WITH_STATIC_LIB)
endif (BUILD_STATIC_LIB)

message(STATUS "Threads_FOUND=${Threads_FOUND}")
