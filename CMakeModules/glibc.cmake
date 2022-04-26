# - Check glibc version
# CHECK_GLIBC_VERSION()
#
# Once done this will define
#
#   GLIBC_VERSION - glibc version
#

# required for list(TRANSFORM ...)
cmake_minimum_required(VERSION 3.12.0)

MACRO (CHECK_GLIBC_VERSION)
    EXECUTE_PROCESS (
        COMMAND ${CMAKE_C_COMPILER} -print-file-name=libc.so.6
        OUTPUT_VARIABLE GLIBC
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    CHECK_GLIBC_VERSION_FILENAME()

    if (NOT GLIBC_VERSION MATCHES "^[0-9.]+$")
        CHECK_GLIBC_VERSION_STRINGS()
    endif()

    IF (NOT GLIBC_VERSION MATCHES "^[0-9.]+$")
        MESSAGE (FATAL_ERROR "Unknown glibc version: ${GLIBC_VERSION}")
    ELSE ()
        MESSAGE ("glibc version ${GLIBC_VERSION} found")
    ENDIF ()
ENDMACRO (CHECK_GLIBC_VERSION)

macro(CHECK_GLIBC_VERSION_FILENAME)
    GET_FILENAME_COMPONENT (GLIBC ${GLIBC} REALPATH)
    GET_FILENAME_COMPONENT (GLIBC_VERSION ${GLIBC} NAME)
    STRING (REPLACE "libc-" "" GLIBC_VERSION ${GLIBC_VERSION})
    STRING (REPLACE ".so" "" GLIBC_VERSION ${GLIBC_VERSION})
endmacro()

# decodes the glibc version by looking for GLIBC_x.x strings in the library
macro(CHECK_GLIBC_VERSION_STRINGS)
    execute_process(
        COMMAND "strings" "${GLIBC}"
        OUTPUT_VARIABLE GLIBC_STRINGS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE GLIC_STRINGS_RESULT_CODE
    )
    if(NOT GLIC_STRINGS_RESULT_CODE EQUAL 0)
        message(FATAL_ERROR "Failed to find glibc version: failed at `strings ${GLIBC}`")
    endif ()
    # convert from newline delimited strings to CMake array
    set(GLIBC_VERSION_REGEX "GLIBC_([0-9.]+\.[0-9.]+)")
    string(REGEX MATCHALL "${GLIBC_VERSION_REGEX}" GLIBC_VERSION_STRINGS_ARRAY "${GLIBC_STRINGS}")
    string(REPLACE "GLIBC_" "" GLIBC_VERSION_ARRAY "${GLIBC_VERSION_STRINGS_ARRAY}")
    if (CMAKE_VERSION VERSION_GREATER 3.17)
        # COMPARE NATURAL for sorting version numbers was only added in 3.18
        # However, normally in glibc, they're in ascending order anyway,
        # so we should be able to ignore sort
        list(SORT GLIBC_VERSION_ARRAY COMPARE NATURAL ORDER ASCENDING)
    endif()
    list(GET GLIBC_VERSION_ARRAY -1 GLIBC_VERSION)
    message("Found highest glibc version ${GLIBC_VERSION}")
endmacro(CHECK_GLIBC_VERSION_STRINGS)
