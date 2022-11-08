#[=======================================================================[.rst:
FindPCAP
-------

Finds libpcap, the LIBpcap interface to various kernel packet capture mechanism.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``PCAP::pcap``
  The PCAP library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``PCAP_FOUND``
  True if the system has the PCAP library.
``PCAP_INCLUDE_DIRS``
  Include directories needed to use PCAP.
``PCAP_LIBRARIES``
  Libraries needed to link to PCAP.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``PCAP_INCLUDE_DIR``
  The directory containing ``PCAP.h``.
``PCAP_LIBRARY``
  The path to the PCAP library.

#]=======================================================================]
cmake_minimum_required(VERSION 3.13.0)

find_package(PkgConfig)
pkg_check_modules(PC_PCAP QUIET PCAP)

find_path(PCAP_INCLUDE_DIR pcap.h
  HINTS ${PC_PCAP_INCLUDEDIR} ${PC_PCAP_INCLUDE_DIRS})

find_library(PCAP_LIBRARY NAMES libpcap pcap
  HINTS ${PC_PCAP_LIBDIR} ${PC_PCAP_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
  FOUND_VAR PCAP_FOUND
  REQUIRED_VARS
    PCAP_LIBRARY
    PCAP_INCLUDE_DIR
)

if(PCAP_FOUND AND NOT TARGET PCAP::pcap)
    set(PCAP_LIBRARIES PCAP::pcap)
    set(PCAP_INCLUDE_DIRS "${PCAP_INCLUDE_DIR}")

    add_library(PCAP::pcap UNKNOWN IMPORTED)
    set_target_properties(PCAP::pcap PROPERTIES
        IMPORTED_LOCATION "${PCAP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIRS}"
        INTERFACE_LINK_LIBRARIES "${PCAP_LIBRARIES}"
    )
    target_compile_definitions(
      # pcap requires BSD types to be defined, e.g. u_int/u_short/u_char
      # the following syntax works for uClibc, glibc, musl libc
      PCAP::pcap INTERFACE
        "_BSD_SOURCE" # deprecated in glibc >2.20
        "_DEFAULT_SOURCE" # only added in glibc >2.19, musl >=1.1.5
    )
endif()
