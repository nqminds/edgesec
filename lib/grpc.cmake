# Fetch and Compile libgrpc
if (BUILD_GRPC_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBGRPC_INSTALL_ROOT ${CMAKE_CURRENT_BINARY_DIR}/lib)
  set(LIBGRPC_INSTALL_DIR ${LIBGRPC_INSTALL_ROOT}/grpc)
  set(LIBGRPC_INCLUDE_PATH ${LIBGRPC_INSTALL_DIR}/include)
  set(LIBGRPC_LIB_DIR "${LIBGRPC_INSTALL_DIR}/lib")
  set(LIBGRPC_BIN_DIR "${LIBGRPC_INSTALL_DIR}/bin")

  find_library(LIBGRPC_PLUGIN_SUPPORT_LIB NAMES grpc_plugin_support libgrpc_plugin_support PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
  find_library(LIBGRPC_LIB NAMES grpc libgrpc PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
  find_library(LIBGRPC_CRYPTO_LIB NAMES crypto libcrypto PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
  find_library(LIBGRPCPP_LIB NAMES grpc++ libgrpc++ PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
  find_library(LIBPROTOBUF_LIB NAMES protobuf libprotobuf PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
  find_library(LIBGRPCPP_REFLECTION_LIB NAMES grpc++_reflection libgrpc++_reflection PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
  find_program(PROTOC_BIN NAMES protoc PATHS "${LIBGRPC_BIN_DIR}" NO_DEFAULT_PATH)
  find_program(GRPC_CPP_PLUGIN_BIN NAMES grpc_cpp_plugin PATHS "${LIBGRPC_BIN_DIR}" NO_DEFAULT_PATH)
  find_program(GRPC_CPP_PLUGIN_SH NAMES grpc_cpp_plugin.sh PATHS "${LIBGRPC_BIN_DIR}" NO_DEFAULT_PATH)
  
  if (LIBGRPCPP_LIB AND LIBPROTOBUF_LIB AND LIBGRPCPP_REFLECTION_LIB AND PROTOC_BIN AND GRPC_CPP_PLUGIN_BIN)
    message("Found libgrpc_plugin_support library: ${LIBGRPC_PLUGIN_SUPPORT_LIB}")
    message("Found libgrpc library: ${LIBGRPC_LIB}")
    message("Found grpc libcrypto library: ${LIBGRPC_CRYPTO_LIB}")
    message("Found libgrpc++ library: ${LIBGRPCPP_LIB}")
    message("Found libprotobuf library: ${LIBPROTOBUF_LIB}")
    message("Found grpc++_reflection library: ${LIBGRPCPP_REFLECTION_LIB}")
    message("Found protoc binary: ${PROTOC_BIN}")
    message("Found grpc_cpp_plugin binary: ${GRPC_CPP_PLUGIN_BIN}")
  ELSE ()
    execute_process(COMMAND bash ${CMAKE_SOURCE_DIR}/lib/compile_grpc.sh ${LIBGRPC_INSTALL_ROOT})
    find_library(LIBGRPC_PLUGIN_SUPPORT_LIB NAMES grpc_plugin_support libgrpc_plugin_support PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
    find_library(LIBGRPC_LIB NAMES grpc libgrpc PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
    find_library(LIBGRPC_CRYPTO_LIB NAMES crypto libcrypto PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
    find_library(LIBGRPCPP_LIB NAMES grpc++ libgrpc++ PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
    find_library(LIBPROTOBUF_LIB NAMES protobuf libprotobuf PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
    find_library(LIBGRPCPP_REFLECTION_LIB NAMES grpc++_reflection libgrpc++_reflection PATHS "${LIBGRPC_LIB_DIR}" NO_DEFAULT_PATH)
    find_program(PROTOC_BIN NAMES protoc PATHS "${LIBGRPC_BIN_DIR}" NO_DEFAULT_PATH)
    find_program(GRPC_CPP_PLUGIN_BIN NAMES grpc_cpp_plugin PATHS "${LIBGRPC_BIN_DIR}" NO_DEFAULT_PATH)

    file(WRITE ${LIBGRPC_INSTALL_DIR}/grpc_cpp_plugin.tmp
    "#!/bin/bash
    set -e
    LD_LIBRARY_PATH=${LIBGRPC_LIB_DIR} ${GRPC_CPP_PLUGIN_BIN} \"$@\"
    "
    )

    file(
      COPY ${LIBGRPC_INSTALL_DIR}/grpc_cpp_plugin.tmp
      DESTINATION ${LIBGRPC_BIN_DIR}
      FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )

    file(RENAME ${LIBGRPC_BIN_DIR}/grpc_cpp_plugin.tmp ${LIBGRPC_BIN_DIR}/grpc_cpp_plugin.sh)
    file(REMOVE  ${LIBGRPC_INSTALL_DIR}/grpc_cpp_plugin.tmp)
    find_program(GRPC_CPP_PLUGIN_SH NAMES grpc_cpp_plugin.sh PATHS "${LIBGRPC_BIN_DIR}" NO_DEFAULT_PATH)
  endif ()



  #set(RE2_BUILD_TESTING OFF CACHE BOOL "RE2 test flag" FORCE)
  #FetchContent_Declare(
  #  gRPC
  #  GIT_REPOSITORY https://github.com/grpc/grpc
  #  GIT_TAG        v1.36.4
  #)
  #set(FETCHCONTENT_QUIET OFF)
  #FetchContent_MakeAvailable(gRPC)
  #FetchContent_GetProperties(gRPC SOURCE_DIR GRPC_SOURCE_DIR)
  #set(_PROTOBUF_LIBPROTOBUF libprotobuf)
  #set(_REFLECTION grpc++_reflection)
  #set(_PROTOBUF_PROTOC $<TARGET_FILE:protoc>)
  #set(_GRPC_GRPCPP grpc++)
  #set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:grpc_cpp_plugin>)  
endif ()
