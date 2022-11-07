#[=======================================================================[.rst:
src/capture
-------

EDGESec capture service.

This file declares the function CMake ``edgesecAddCaptureMiddleware``.
You can use this CMake function to add custom middlewares to EDGESec.

The general signature is
.. code-block:: cmake

   # where src/example.c contains
   # `extern struct capture_middleware <C_NAME_OF_MIDDLEWARE_VARIABLE>;`
   add_library(<CMAKE_TARGET_CONTAINING_YOUR_MIDDLEWARE> src/example.c)

   edgesecAddCaptureMiddleware(
        MIDDLEWARE_TARGET <CMAKE_TARGET_CONTAINING_YOUR_MIDDLEWARE>
        MIDDLEWARE_STRUCT <C_NAME_OF_MIDDLEWARE_VARIABLE>
   )

``MIDDLEWARE_STRUCT`` must be a `struct capture_middleware`, where `capture_middleware`
is included from `middleware.h`.

Example `my_middlewares.h`
.. code-block:: c
  #include "middleware.h"
  extern struct capture_middleware my_first_middleware;
  extern struct capture_middleware my_second_middleware;

Example: `my_middleware.c`
.. code-block:: c
  #include "my_middleware.h"
  struct capture_middleware my_first_middleware = {
    .init = my_middleware_init_function,
    .process = my_middleware_process_function,
    .free = my_middleware_cleaner_function,
  };
  struct capture_middleware my_second_middleware = {
    // ...
  };

Example: `CMakeLists.txt`
.. code-block:: cmake
   add_library(my_middlewares src/my_middlewares.c)

   include(EDGESec)

   edgesecAddCaptureMiddleware(
        MIDDLEWARE_TARGET my_middlewares
        MIDDLEWARE_STRUCT my_first_middleware
   )
   edgesecAddCaptureMiddleware(
        MIDDLEWARE_TARGET my_middlewares
        MIDDLEWARE_STRUCT my_second_middleware
   )
#]=======================================================================]

if (USE_CAPTURE_SERVICE)
  # some of these files are required, even if USE_*_MIDDLEWARE is off
  add_subdirectory(./middlewares/cleaner_middleware)
  add_subdirectory(./middlewares/header_middleware)
  add_subdirectory(./middlewares/pcap_middleware)
  add_subdirectory(./middlewares/tap_middleware)
  add_subdirectory(./middlewares/protobuf_middleware EXCLUDE_FROM_ALL)

  add_library(capture_config INTERFACE) # header only library
  target_link_libraries(capture_config INTERFACE os)

  add_library(pcap_service pcap_service.c)
  target_link_libraries(pcap_service PUBLIC LibUTHash::LibUTHash PCAP::pcap PRIVATE net log os)

  add_library(capture_service capture_service.c)
  target_include_directories(capture_service PRIVATE ${PROJECT_BINARY_DIR})
  target_link_libraries(
    capture_service
    PUBLIC PCAP::pcap middlewares_list
    PRIVATE
      dns_decoder pcap_service pcap_queue packet_queue packet_decoder squeue
      eloop iface log os hashmap SQLite::SQLite3 Threads::Threads)

  set(CAPTURE_MIDDLEWARES "")

  function(_edgesec_buildMiddlewaresSource)
    set(oneValueArgs
      CAPTURE_MIDDLEWARES
    )
    cmake_parse_arguments(
      PARSE_ARGV 0 arg "" "${oneValueArgs}" ""
    )

    if (NOT DEFINED arg_CAPTURE_MIDDLEWARES)
      configure_file(
        "middlewares_list.c.in"
        "middlewares_list.c"
      )
      return()
    endif()

    # C array initialiser for capture middleware
    # e.g. `middleware1, middleware2`
    list(JOIN arg_CAPTURE_MIDDLEWARES ", " _CAPTURE_MIDDLEWARES_LIST_INITIALISER)

    set(_CAPTURE_MIDDLEWARES_DEFINITIONS "extern struct capture_middleware ${_CAPTURE_MIDDLEWARES_LIST_INITIALISER};")

    configure_file(
      "middlewares_list.c.in"
      "middlewares_list.c"
    )
  endfunction()

  # creates initial empty middlewares.c file
  # future calls to edgesecAddCaptureMiddleware() will create middlewares.c
  _edgesec_buildMiddlewaresSource(CAPTURE_MIDDLEWARES "${CAPTURE_MIDDLEWARES}")
  add_library(middlewares_list "${CMAKE_CURRENT_BINARY_DIR}/middlewares_list.c")
  target_include_directories(middlewares_list PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(middlewares_list PUBLIC LibUTHash::LibUTHash SQLite::SQLite3 PCAP::pcap eloop)

  function(edgesecAddCaptureMiddleware)
    set(oneValueArgs
      MIDDLEWARE_TARGET MIDDLEWARE_STRUCT
    )
    cmake_parse_arguments(
      PARSE_ARGV 0 arg "" "${oneValueArgs}" ""
    )
    if (NOT DEFINED arg_MIDDLEWARE_TARGET)
      message(FATAL_ERROR "MIDDLEWARE_TARGET is not defined for edgesecAddCaptureMiddleware")
    elseif(NOT TARGET "${arg_MIDDLEWARE_TARGET}")
      message(FATAL_ERROR "MIDDLEWARE_TARGET ${arg_MIDDLEWARE_TARGET} is not a CMake target")
    elseif(NOT DEFINED arg_MIDDLEWARE_STRUCT)
      message(FATAL_ERROR "MIDDLEWARE_STRUCT is not defined for edgesecAddCaptureMiddleware")
    endif()

    target_link_libraries(middlewares_list PRIVATE "${arg_MIDDLEWARE_TARGET}")
    list(APPEND CAPTURE_MIDDLEWARES "${arg_MIDDLEWARE_STRUCT}")
    set(CAPTURE_MIDDLEWARES "${CAPTURE_MIDDLEWARES}" PARENT_SCOPE)
    _edgesec_buildMiddlewaresSource(CAPTURE_MIDDLEWARES "${CAPTURE_MIDDLEWARES}")
  endfunction()

  if (USE_CLEANER_MIDDLEWARE)
    edgesecAddCaptureMiddleware(MIDDLEWARE_TARGET cleaner_middleware MIDDLEWARE_STRUCT cleaner_middleware)
  endif ()
  if (USE_HEADER_MIDDLEWARE)
    edgesecAddCaptureMiddleware(MIDDLEWARE_TARGET header_middleware MIDDLEWARE_STRUCT header_middleware)
  endif ()
  if (USE_PCAP_MIDDLEWARE)
    edgesecAddCaptureMiddleware(MIDDLEWARE_TARGET pcap_middleware MIDDLEWARE_STRUCT pcap_middleware)
  endif ()
  if (USE_TAP_MIDDLEWARE)
    edgesecAddCaptureMiddleware(MIDDLEWARE_TARGET tap_middleware MIDDLEWARE_STRUCT tap_middleware)
  endif ()
  if (USE_PROTOBUF_MIDDLEWARE)
    edgesecAddCaptureMiddleware(MIDDLEWARE_TARGET protobuf_middleware MIDDLEWARE_STRUCT protobuf_middleware)
  endif ()
endif()
