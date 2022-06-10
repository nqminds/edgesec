#[=======================================================================[.rst:
FindNL
-------

Finds libnl-3, the linux netlink protocol library

In Debian/Ubuntu, they may be called:
  ``libnl-3-dev libnl-genl-3dev libnl-nf-3-dev libnl-route-3-dev``

This module accept optional ``COMPONENTS`` to check specific libraries:

::

  COMPONENTS: core route genl nf

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``NL::<component>``
  Target for specific component dependency (shared or static library);
  ``<component>`` name is lower-case.


Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``NL_FOUND``
  True if the system has the NL library.
``NL_<component>_FOUND``
  True if component ``<component>`` was found
``NL_INCLUDE_DIRS``
  Include directories needed to use libnl.
``NL_LIBRARIES``
  Libraries needed to link to libnl.

#]=======================================================================]
find_package(PkgConfig QUIET)

set(NL_SEARCH_COMPOMPONENTS core route genl nf)

foreach(_comp ${NL_SEARCH_COMPOMPONENTS})
  if(_comp STREQUAL "core")
    set(module_spec nl)
  else()
    set(module_spec nl-${_comp})
  endif()

  if(PKG_CONFIG_FOUND)
    # use pkg_config to find hints for library/include paths
    pkg_search_module(
        PC_NL_${_comp}
        QUIET
        lib${module_spec} lib${module_spec}-3 lib${module_spec}-3.0
    )
  endif()

  find_library(
      NL_${_comp}_LIBRARY
      NAMES
        ${module_spec} ${module_spec}-3 ${module_spec}-3.0
      HINTS "${PC_NL_${_comp}_LIBDIR}" "${PC_NL_${_comp}_LIBRARY_DIRS}"
  )

  if(NL_${_comp}_LIBRARY AND EXISTS "${NL_${_comp}_LIBRARY}")
    set(NL_${_comp}_FOUND TRUE)
  else()
    set(NL_${_comp}_FOUND FALSE)
  endif()
endforeach()

find_path(NL_INCLUDE_DIR
  NAMES netlink/netlink.h
  HINTS "${PC_NL_core_INCLUDEDIR}" "${PC_NL_core_INCLUDE_DIRS}"
  PATH_SUFFIXES libnl3
)

set(NL_LIBRARIES "${NL_core_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NL
  REQUIRED_VARS NL_INCLUDE_DIR NL_core_LIBRARY
  HANDLE_COMPONENTS # will automatically check NL_${_comp}_FOUND
  REASON_FAILURE_MESSAGE
    "Netlink libnl development libraries could not be found.
    On Debian/Ubuntu, they may be called `libnl-3-dev libnl-genl-3-dev`"

)

set(NL_INCLUDE_DIRS "${NL_INCLUDE_DIR}")


if(NL_FOUND)
  foreach(_comp "core" ${NL_SEARCH_COMPOMPONENTS})
    if(NOT TARGET NL::${_comp})
      add_library(NL::${_comp} UNKNOWN IMPORTED)
      set_target_properties(NL::${_comp} PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${NL_INCLUDE_DIR}"
        IMPORTED_LOCATION "${NL_${_comp}_LIBRARY}"
        VERSION_VAR NL_core_VERSION
      )
      if(NOT _comp STREQUAL "core")
        set_target_properties(NL::${_comp}
          PROPERTIES INTERFACE_LINK_LIBRARIES NL::core
        )
      endif()
    endif()
  endforeach()
endif()
