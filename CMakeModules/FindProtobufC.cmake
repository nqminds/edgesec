# SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
# SPDX-License-Identifier: LGPL-3.0-or-later

#[=======================================================================[.rst:
FindProtobufC
-------

Finds protobuf-c, a C implementation of Google Protocol Buffers data
serialization format.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``protobufc::protobufc``
  The protobuf-c library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``ProtobufC_FOUND``
  True if the system has the protobuf-c library.
``ProtobufC_VERSION``
  The version of the protobuf-c library which was found.
``ProtobufC_INCLUDE_DIRS``
  Include directories needed to use protobuf-c.
``ProtobufC_LIBRARIES``
  Libraries needed to link to protobuf-c.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``ProtobufC_INCLUDE_DIR``
  The directory containing ``protobuf-c/protobuf-c.h``.
``ProtobufC_LIBRARY``
  The path to the protobuf-c library.

#]=======================================================================]
cmake_minimum_required(VERSION 3.13.0)

find_package(PkgConfig)
pkg_check_modules(PC_ProtobufC libprotobuf-c QUIET)

find_path(ProtobufC_INCLUDE_DIR
  NAMES "protobuf-c/protobuf-c.h"
  PATHS ${PC_ProtobufC_INCLUDE_DIRS}
)
find_library(ProtobufC_LIBRARY
  NAMES libprotobuf-c protobuf-c
  PATHS ${PC_ProtobufC_LIBRARY_DIRS}
)

set(ProtobufC_VERSION ${PC_ProtobufC_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ProtobufC
  FOUND_VAR ProtobufC_FOUND
  REQUIRED_VARS
    ProtobufC_LIBRARY
    ProtobufC_INCLUDE_DIR
  VERSION_VAR ProtobufC_VERSION
)

if(ProtobufC_FOUND AND NOT TARGET ProtobufC::ProtobufC)
  add_library(protobufc::protobufc UNKNOWN IMPORTED)
  set_target_properties(protobufc::protobufc PROPERTIES
      IMPORTED_LOCATION "${ProtobufC_LIBRARY}"
      INTERFACE_COMPILE_OPTIONS "${PC_ProtobufC_CFLAGS_OTHER}"
      INTERFACE_INCLUDE_DIRECTORIES "${ProtobufC_INCLUDE_DIR}"
  )

  set(ProtobufC_LIBRARIES protobufc::protobufc)
  set(ProtobufC_INCLUDE_DIRS ${ProtobufC_INCLUDE_DIR})
  set(ProtobufC_DEFINITIONS ${PC_ProtobufC_CFLAGS_OTHER})
endif()
