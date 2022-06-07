#[=======================================================================[.rst:
FindUCI
-------

Finds the OpenWRT Unified Configuration Interface library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``OpenWRT::UCI``
  The UCI library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``UCI_FOUND``
  True if the system has the UCI library.
``UCI_INCLUDE_DIRS``
  Include directories needed to use UCI.
``UCI_LIBRARIES``
  Libraries needed to link to UCI.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``UCI_INCLUDE_DIR``
  The directory containing ``UCI.h``.
``UCI_LIBRARY``
  The path to the UCI library.

#]=======================================================================]
cmake_minimum_required(VERSION 3.13.0)

find_package(PkgConfig)
pkg_check_modules(PC_UCI QUIET uci)

find_path(UCI_INCLUDE_DIR uci.h
  HINTS ${PC_UCI_INCLUDEDIR} ${PC_UCI_INCLUDE_DIRS})

find_library(UCI_LIBRARY NAMES libuci uci
  HINTS ${PC_UCI_LIBDIR} ${PC_UCI_LIBRARY_DIRS})

find_library(UBOX_LIBRARY NAMES libubox ubox
  HINTS ${PC_UBOX_LIBDIR} ${PC_UBOX_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(UCI
  FOUND_VAR UCI_FOUND
  REQUIRED_VARS
    UCI_LIBRARY
    UCI_INCLUDE_DIR
    UBOX_LIBRARY
)

if(UCI_FOUND AND NOT TARGET OpenWRT::UCI)
    add_library(OpenWRT::UCI UNKNOWN IMPORTED)
    set_target_properties(OpenWRT::UCI PROPERTIES
        IMPORTED_LOCATION "${UCI_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${UCI_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${UBOX_LIBRARY}"
    )

  set(UCI_LIBRARIES OpenWRT::UCI)
  set(UCI_INCLUDE_DIRS ${UCI_INCLUDE_DIR})
endif()
