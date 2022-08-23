# Compile library libnetlink
if (BUILD_NETLINK_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBNETLINK_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/libnetlink")
  FetchContent_Declare(
    libnetlink_src
    SOURCE_DIR "${LIBNETLINK_SOURCE_DIR}"
  )
  # creates the targets libnetlink, ll_map, rt_names, utils

  set(CMAKE_C_EXTENSIONS ON) # libnetlink uses non-POSIX C

  FetchContent_MakeAvailable(libnetlink_src)

  if (TARGET libnetlink)
    set(LIBNETLINK_LIB libnetlink)
    set(LL_MAP_LIB ll_map)
    set(UTILS_LIB utils)
    set(RT_NAMES_LIB rt_names)
  else ()
    message(FATAL_ERROR "Target libnetlink was not defined")
  endif()
endif()
