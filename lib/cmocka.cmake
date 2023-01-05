# Copyright 2020 OLIVIER LE DOEUFF
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software
# and associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Compile the cmocka library
if (BUILD_ONLY_DOCS OR NOT (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING))
  # skip building cmocka, not needed
elseif (BUILD_CMOCKA_LIB)
  include(FetchContent)

  set(CMOCKA_GIT_SHA "55c444ee6ab77f27b188b09b1a32792d3a02d2f1")
  FetchContent_Declare(
    cmocka
    # Use upstream in development cmocka version to fix some bugs
    # - Adds Cheri Hybrid support https://gitlab.com/cmocka/cmocka/-/issues/38
    # - Support building with `C_EXTENSIONS` https://gitlab.com/cmocka/cmocka/-/merge_requests/51
    # - Work-around for FreeBSD libc bug https://gitlab.com/cmocka/cmocka/-/merge_requests/53
    # - CHERI PureCap fixes
    #   - Use `__builtin_align_down` to align pointers https://gitlab.com/cmocka/cmocka/-/merge_requests/55
    #   - Remove casts from `uintptr_t` to `uintmax_t` https://gitlab.com/cmocka/cmocka/-/merge_requests/56
    URL "https://gitlab.com/api/v4/projects/aloisklink%2Fcmocka/repository/archive.tar.bz2?sha=${CMOCKA_GIT_SHA}"
    URL_HASH SHA256=496c8628a7e9fd000a59540fab97d21fdd3721a8e8b7930c55bdef78acf301f7
    DOWNLOAD_NAME "cmocka-${CMOCKA_GIT_SHA}.tar.bz2"
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default dir
  )

  set(WITH_STATIC_LIB ON CACHE BOOL "CMocka: Build with a static library" FORCE)
  set(WITH_CMOCKERY_SUPPORT OFF CACHE BOOL "CMocka: Install a cmockery header" FORCE)
  set(WITH_EXAMPLES OFF CACHE BOOL "CMocka: Build examples" FORCE)
  set(UNIT_TESTING OFF CACHE BOOL "CMocka: Build with unit testing" FORCE)
  set(PICKY_DEVELOPER OFF CACHE BOOL "CMocka: Build with picky developer flags" FORCE)

  FetchContent_MakeAvailable(cmocka)

  # avoid install `cmocka` when running `make install`
  # work around until https://gitlab.kitware.com/cmake/cmake/-/issues/20167 is fixed
  if(IS_DIRECTORY "${cmocka_SOURCE_DIR}")
    set_property(DIRECTORY ${cmocka_SOURCE_DIR} PROPERTY EXCLUDE_FROM_ALL YES)
  endif()

  if (NOT TARGET cmocka::cmocka)
    add_library(cmocka::cmocka ALIAS cmocka)
  endif(NOT TARGET cmocka::cmocka)
else ()
  find_package(cmocka 1.1.5 REQUIRED)
  add_library(cmocka::cmocka UNKNOWN IMPORTED)
  set_target_properties(cmocka::cmocka PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${CMOCKA_INCLUDE_DIR}
    IMPORTED_LOCATION ${CMOCKA_LIBRARY}
)
endif ()
