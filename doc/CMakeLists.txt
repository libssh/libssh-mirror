#
# Build the documentation
#
find_package(Doxygen)

if (DOXYGEN_FOUND)
    doxygen_add_docs(docs
                     ${CMAKE_SOURCE_DIR}/src
                     ${CMAKE_CURRENT_SOURCE_DIR})
endif()
