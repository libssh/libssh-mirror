include(CheckCCompilerFlag)

macro(add_c_compiler_flag _COMPILER_FLAG _OUTPUT_VARIABLE)
    string(TOUPPER ${_COMPILER_FLAG} _COMPILER_FLAG_NAME)
    string(REGEX REPLACE "^-" "" _COMPILER_FLAG_NAME "${_COMPILER_FLAG_NAME}")
    string(REGEX REPLACE "(-|=|\ )" "_" _COMPILER_FLAG_NAME "${_COMPILER_FLAG_NAME}")

    check_c_compiler_flag("${_COMPILER_FLAG}" WITH_${_COMPILER_FLAG_NAME}_FLAG)
    if (WITH_${_COMPILER_FLAG_NAME}_FLAG)
        #string(APPEND ${_OUTPUT_VARIABLE} "${_COMPILER_FLAG} ")
        list(APPEND ${_OUTPUT_VARIABLE} ${_COMPILER_FLAG})
    endif()
endmacro()
