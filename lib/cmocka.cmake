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
if (BUILD_CMOCKA_LIB AND NOT (BUILD_ONLY_DOCS) AND NOT (CMAKE_CROSSCOMPILING))
  include(FetchContent)

  FetchContent_Declare(
    cmocka
    # URL https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz
    # URL_HASH SHA256=f0ccd8242d55e2fd74b16ba518359151f6f8383ff8aef4976e48393f77bba8b6

    # Use upstream in development cmocka version to fix https://gitlab.com/cmocka/cmocka/-/issues/38
    # Adds 64-bit Muslibc, Cheri ARM/Morello/128-bit pointer support
    GIT_REPOSITORY https://gitlab.com/cmocka/cmocka.git
    # latest master commit as of 2022-08-10
    GIT_TAG 59dc0013f9f29fcf212fe4911c78e734263ce24c
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default
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
elseif (NOT BUILD_ONLY_DOCS AND NOT (CMAKE_CROSSCOMPILING))
  find_package(cmocka 1.1.5 REQUIRED)
  add_library(cmocka::cmocka UNKNOWN IMPORTED)
  set_target_properties(cmocka::cmocka PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${CMOCKA_INCLUDE_DIR}
    IMPORTED_LOCATION ${CMOCKA_LIBRARY}
)
endif ()
