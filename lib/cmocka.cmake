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
    URL https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz
    URL_HASH SHA256=f0ccd8242d55e2fd74b16ba518359151f6f8383ff8aef4976e48393f77bba8b6
  )

  set(WITH_STATIC_LIB ON CACHE BOOL "CMocka: Build with a static library" FORCE)
  set(WITH_CMOCKERY_SUPPORT OFF CACHE BOOL "CMocka: Install a cmockery header" FORCE)
  set(WITH_EXAMPLES OFF CACHE BOOL "CMocka: Build examples" FORCE)
  set(UNIT_TESTING OFF CACHE BOOL "CMocka: Build with unit testing" FORCE)
  set(PICKY_DEVELOPER OFF CACHE BOOL "CMocka: Build with picky developer flags" FORCE)

  FetchContent_MakeAvailable(cmocka)
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

