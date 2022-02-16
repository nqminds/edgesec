# Compile library libnetlink
if (USE_NETLINK_SERVICE)
  add_compile_definitions(WITH_NETLINK_SERVICE)
endif ()

if (BUILD_NETLINK_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBNETLINK_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/libnetlink")
  set(LIBNETLINK_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBNETLINK_INSTALL_DIR "${LIBNETLINK_INSTALL_ROOT}/netlink")
  set(LIBNETLINK_INCLUDE_PATH "${LIBNETLINK_INSTALL_DIR}/include")
  set(LIBNETLINK_UAPI_INCLUDE_PATH "${LIBNETLINK_INCLUDE_PATH}/uapi")
  set(LIBNETLINK_LIB_PATH ${LIBNETLINK_INSTALL_DIR}/lib)
  find_library(LIBNETLINK_LIB NAMES libnetlink PATHS "${LIBNETLINK_LIB_PATH}" NO_DEFAULT_PATH)
  if (LIBNETLINK_LIB)
    message("Found libnetlink library: ${LIBNETLINK_LIB}")
  ELSE ()
    FetchContent_Declare(
      libnetlink_src
      SOURCE_DIR "${LIBNETLINK_SOURCE_DIR}"
    )
    FetchContent_Populate(libnetlink_src)
    execute_process(COMMAND ${CMAKE_COMMAND}
      -B build/ -S "${libnetlink_src_SOURCE_DIR}"
      "-DCMAKE_INSTALL_PREFIX=${LIBNETLINK_INSTALL_DIR}"
      # Pass location of MNL found with FindMNL.cmake
      "-DMNL_INCLUDE_DIR=${MNL_INCLUDE_DIR}"
      "-DMNL_LIBRARY=${MNL_LIBRARY}"
      # Pass C/CXX compiler for gcc/cross-compiling
      "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}"
      "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
      WORKING_DIRECTORY "${libnetlink_src_BINARY_DIR}"
    )
    execute_process(COMMAND ${CMAKE_COMMAND}
      --build build/
      WORKING_DIRECTORY "${libnetlink_src_BINARY_DIR}"
    )
    execute_process(COMMAND ${CMAKE_COMMAND}
      --install build/
      WORKING_DIRECTORY "${libnetlink_src_BINARY_DIR}"
    )
    find_library(LIBNETLINK_LIB NAMES libnetlink PATHS "${LIBNETLINK_LIB_PATH}" NO_DEFAULT_PATH)
  endif ()
  find_library(LL_MAP_LIB NAMES ll_map PATHS "${LIBNETLINK_LIB_PATH}")
  message("Found ll_map library: ${LL_MAP_LIB}")
  find_library(UTILS_LIB NAMES utils PATHS "${LIBNETLINK_LIB_PATH}")
  message("Found utils library: ${UTILS_LIB}")
  find_library(RT_NAMES_LIB NAMES rt_names PATHS "${LIBNETLINK_LIB_PATH}")
  message("Found rt_names library: ${RT_NAMES_LIB}")
endif ()
