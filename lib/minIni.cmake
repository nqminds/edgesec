# Compile libminini library

option(BUILD_LIB_MININI "Build minIni library" ON)

if (BUILD_ONLY_DOCS)
elseif(BUILD_LIB_MININI)
  FetchContent_Declare(
    libminini_src
    # From 2020-04-22. Matches minIni.* files from https://github.com/nqminds/edgesec/tree/2a18535cb57f7059dba72eb50490bda587291fe8
    URL https://api.github.com/repos/compuphase/minIni/tarball/b40dff4924461272f669814da7d0c9fdc8be6d94
    URL_HASH SHA512=7cab1b3b7732a33eae3450426fe13dc2eac8720052e410521ab0a0e0439c154cf0cf8d7080ce35d8cff36733ed0f44574fd7c85f6a92de4210d8ed4312cb166e
    DOWNLOAD_NAME minIni.tar.gz
  )
  FetchContent_MakeAvailable(libminini_src)

  set(MinIni_INCLUDE_DIR "${libminini_src_SOURCE_DIR}/dev")

  # minIni is Apache 2.0, but has an exclusion for static linking, so we
  # don't need to bother to add a NOTICE/Copyright info to our statically
  # linked binary (although we should consider it in the future, just to be nice)
  add_library(minIni STATIC "${libminini_src_SOURCE_DIR}/dev/minIni.c")

  # We compile in C11 standard mode, so strncasecmp does not exist in <string.h>
  # (according to POSIX standard, they are only in <strings.h>)
  target_compile_definitions(minIni PRIVATE PORTABLE_STRNICMP)
  # needed to include minIni.h and minGlue.h
  target_include_directories(minIni PUBLIC "${MinIni_INCLUDE_DIR}")

  add_library(MinIni::minIni ALIAS minIni)
else()
  # Ubuntu focal (20.04+) already contains libminini-dev package that has minIni
  find_package(MinIni REQUIRED)
endif()
