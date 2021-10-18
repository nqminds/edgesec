cmake_minimum_required(VERSION 3.15.0)
# v3.15 required for add_library(grpc ALIAS)
# due to https://gitlab.kitware.com/cmake/cmake/-/issues/18327

# This file provides the following libraries (with appropriate INCLUDE_DIRS set)
#   grpc++ grpc++_reflection grpc_plugin_support
#
# Additionally, the following variables point to their appropriate binary:
#   GRPC_CPP_PLUGIN PROTOC_BIN

# Fetch and Compile libgrpc
if (BUILD_GRPC_LIB AND NOT (BUILD_ONLY_DOCS))
  FetchContent_Declare(
    gRPC
    GIT_REPOSITORY https://github.com/grpc/grpc
    GIT_TAG        v1.36.4
    GIT_SHALLOW true # only download latest commit
    GIT_PROGRESS true # downloading loads of submodules, so we want to see progress
  )
  set(FETCHCONTENT_QUIET OFF)

  # Warning, overriding default GRPC install directories doesn't fully work
  # GRPC pkgconfig still installs into /usr/share
  # Protobuf still installs into /usr/lib, as well as some other submodules.
  set(CUSTOM_GRPC_INSTALL_LIBS OFF)
  if (CUSTOM_GRPC_INSTALL_LIBS)
    set(LIBGRPC_INSTALL_ROOT ${CMAKE_CURRENT_BINARY_DIR}/lib)
    set(LIBGRPC_INSTALL_DIR ${LIBGRPC_INSTALL_ROOT}/grpc)
    set(LIBGRPC_INCLUDE_PATH ${LIBGRPC_INSTALL_DIR}/include)
    set(LIBGRPC_LIB_DIR "${LIBGRPC_INSTALL_DIR}/lib")
    set(LIBGRPC_BIN_DIR "${LIBGRPC_INSTALL_DIR}/bin")
    # tell GRPC to install all files in ./build/lib/grpc, except shared libs
    set(gRPC_INSTALL_BINDIR ${LIBGRPC_BIN_DIR} CACHE INTERNAL "GRPC bin dir")
    set(gRPC_INSTALL_CMAKEDIR "${LIBGRPC_LIB_DIR}/cmake/grpc" CACHE INTERNAL "GRPC cmake dir")
    # LIBDIR is the only one we install in /usr/lib/x86_64/edgesec
    set(gRPC_INSTALL_LIBDIR "${EDGESEC_private_lib_dir}" CACHE INTERNAL "GRPC shared lib dir")
    set(gRPC_INSTALL_INCLUDEDIR ${LIBGRPC_INCLUDE_PATH} CACHE INTERNAL "GRPC include dir")
    set(gRPC_INSTALL_SHAREDIR "${LIBGRPC_INSTALL_DIR}/share/grpc" CACHE INTERNAL "GRPC share dir (holds CA keys)")

    # GRPC Submodules
    set(CARES_INSTALL OFF CACHE INTERNAL "Disable CARES Installation") # no need to install, since it's static lib
  endif (CUSTOM_GRPC_INSTALL_LIBS)

  set(RE2_BUILD_TESTING OFF CACHE INTERNAL "Disable super slow RE2 tests")

  FetchContent_MakeAvailable(gRPC)

  #if cross-compiling, find host plugin
  if(CMAKE_CROSSCOMPILING)
    find_program(
      GRPC_CPP_PLUGIN grpc_cpp_plugin
      DOC "Path to grpc_cpp_plugin (not needed when building grpc and not cross-compiling)"
      REQUIRED
    )
  else()
    set(GRPC_CPP_PLUGIN $<TARGET_FILE:grpc_cpp_plugin>)
  endif()

  if(CMAKE_CROSSCOMPILING)
    find_program(
      PROTOC_BIN protoc
      DOC "Path to protobuf compiler (not needed when building grpc and not cross-compiling)"
      REQUIRED
    )
  elseif (TARGET protobuf::protoc)
    set(PROTOC_BIN $<TARGET_FILE:protobuf::protoc>)
  else()
    find_program(
      PROTOC_BIN protoc
      DOC "Path to protobuf compiler (not needed when building grpc and not cross-compiling)"
      REQUIRED
    )
  endif()
elseif (NOT (BUILD_ONLY_DOCS))
  # Find pre-installed grpc
  message("Trying to find pre-installed GRPC and Protobuf")
  find_package(gRPC REQUIRED)

  add_library(grpc ALIAS gRPC::grpc)
  add_library(grpc++ ALIAS gRPC::grpc++)
  add_library(grpc++_reflection ALIAS gRPC::grpc++_reflection)

  add_executable(grpc_cpp_plugin ALIAS gRPC::grpc_cpp_plugin)
  set(GRPC_CPP_PLUGIN $<TARGET_FILE:grpc_cpp_plugin>)

  find_package(Protobuf REQUIRED)
  set(PROTOC_BIN $<TARGET_FILE:protobuf::protoc>)

  # grpc_plugin_support library is just a virtual lib pointing to libprotobuf
  add_library(grpc_plugin_support INTERFACE)
  target_link_libraries(grpc_plugin_support
    # INTERFACE protobuf::libprotoc
    INTERFACE protobuf::libprotobuf
  )
endif ()

function(check_targets_exists ARGV)
  foreach(TARGET ${ARGV})
    if (NOT TARGET ${TARGET})
      message(FATAL_ERROR "Target ${TARGET} must exist")
    endif ()
  endforeach()
endfunction()

function(check_vars_defined ARGV)
  foreach(VAR ${ARGV})
    if (NOT DEFINED ${VAR})
      message(FATAL_ERROR "Variable ${VAR} must be defined")
    endif ()
  endforeach()
endfunction()

if (NOT BUILD_ONLY_DOCS)
  check_targets_exists(grpc++ grpc++_reflection grpc_plugin_support)
  check_vars_defined(GRPC_CPP_PLUGIN PROTOC_BIN)
endif (NOT BUILD_ONLY_DOCS)
