#[=======================================================================[.rst:
FindMNL
-------

Finds the libmnl minimalistic Netlink communication library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``MNL::mnl``
  The MNL library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``MNL_FOUND``
  True if the system has the MNL library.
``MNL_VERSION``
  The version of the MNL library which was found.
``MNL_INCLUDE_DIRS``
  Include directories needed to use MNL.
``MNL_LIBRARIES``
  Libraries needed to link to MNL.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``MNL_INCLUDE_DIR``
  The directory containing ``MNL.h``.
``MNL_LIBRARY``
  The path to the MNL library.

#]=======================================================================]
cmake_minimum_required(VERSION 3.13.0)

find_package(PkgConfig)
pkg_check_modules(PC_MNL libmnl QUIET)

find_path(MNL_INCLUDE_DIR
  NAMES "libmnl/libmnl.h"
  PATHS ${PC_MNL_INCLUDE_DIRS}
)
find_library(MNL_LIBRARY
  NAMES libmnl mnl
  PATHS ${PC_MNL_LIBRARY_DIRS}
)

set(MNL_VERSION ${PC_MNL_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MNL
  FOUND_VAR MNL_FOUND
  REQUIRED_VARS
    MNL_LIBRARY
    MNL_INCLUDE_DIR
  VERSION_VAR MNL_VERSION
)

if(MNL_FOUND AND NOT TARGET MNL::mnl)
  if (NOT TARGET MNL::mnl)
    add_library(MNL::mnl UNKNOWN IMPORTED)
    set_target_properties(MNL::mnl PROPERTIES
        IMPORTED_LOCATION "${MNL_LIBRARY}"
        INTERFACE_COMPILE_OPTIONS "${PC_MNL_CFLAGS_OTHER}"
        INTERFACE_INCLUDE_DIRECTORIES "${MNL_INCLUDE_DIR}"
    )
  endif(NOT TARGET MNL::mnl)

  set(MNL_LIBRARIES MNL::mnl)
  set(MNL_INCLUDE_DIRS ${MNL_INCLUDE_DIR})
  set(MNL_DEFINITIONS ${PC_MNL_CFLAGS_OTHER})
endif()
