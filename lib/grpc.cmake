# Fetch and Compile libgrpc
if (BUILD_GRPC_LIB AND NOT (BUILD_ONLY_DOCS))
  set(RE2_BUILD_TESTING OFF CACHE BOOL "RE2 test flag" FORCE)
  FetchContent_Declare(
    gRPC
    GIT_REPOSITORY https://github.com/grpc/grpc
    GIT_TAG        v1.36.4
  )
  set(FETCHCONTENT_QUIET OFF)
  FetchContent_MakeAvailable(gRPC)
  FetchContent_GetProperties(gRPC SOURCE_DIR GRPC_SOURCE_DIR)
  message("${GRPC_SOURCE_DIR}/third_party/re2")
  set(_PROTOBUF_LIBPROTOBUF libprotobuf)
  set(_REFLECTION grpc++_reflection)
  set(_PROTOBUF_PROTOC $<TARGET_FILE:protoc>)
  set(_GRPC_GRPCPP grpc++)
  set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:grpc_cpp_plugin>)  
endif ()
