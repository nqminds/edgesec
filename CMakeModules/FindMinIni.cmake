# SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
# SPDX-License-Identifier: LGPL-3.0-or-later

#[=======================================================================[.rst:
FindMinIni
------------

Find Compuphase's MinIni include directory and library.

Imported Targets
^^^^^^^^^^^^^^^^

An :ref:`imported target <Imported targets>` named
``MinIni::minIni`` is provided if minIni has been found.

Result Variables
^^^^^^^^^^^^^^^^

This module defines the following variables:

``MinIni_FOUND``
  True if MinIni was found, false otherwise.
``MinIni_INCLUDE_DIRS``
  Include directories needed to include minIni headers.
``MinIni_LIBRARIES``
  Libraries needed to link to minIni.

Cache Variables
^^^^^^^^^^^^^^^

This module uses the following cache variables:

``MinIni_LIBRARY``
  The location of the minIni library file.
``MinIni_INCLUDE_DIR``
  The location of the minIni include directory containing ``minIni/minIni.h``.

The cache variables should not be used by project code.
They may be set by end users to point at minIni components.
#]=======================================================================]

# Warning, Ubuntu 22.04 creates a /usr/lib/x86_64-linux-gnu/pkgconfig/minIni.pc
# file, but it's broken and doesn't work

#-----------------------------------------------------------------------------
find_library(MinIni_LIBRARY
  NAMES minIni
)
mark_as_advanced(MinIni_LIBRARY)

find_path(MinIni_INCLUDE_DIR
  NAMES minIni.h
  PATH_SUFFIXES minIni
  # On Ubuntu 20.04, located under /usr/include/minIni/minIni.h
  # On Ubuntu 22.04, located under /usr/include/minIni.h
)
mark_as_advanced(MinIni_INCLUDE_DIR)

#-----------------------------------------------------------------------------
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(MinIni
  FOUND_VAR MinIni_FOUND
  REQUIRED_VARS MinIni_LIBRARY MinIni_INCLUDE_DIR
  )
set(MinIni_FOUND ${MinIni_FOUND})

#-----------------------------------------------------------------------------
# Provide documented result variables and targets.
if(MinIni_FOUND)
  set(MinIni_INCLUDE_DIRS ${MinIni_INCLUDE_DIR})
  set(MinIni_LIBRARIES ${MinIni_LIBRARY})
  if(NOT TARGET MinIni::minIni)
    add_library(MinIni::minIni UNKNOWN IMPORTED)
    set_target_properties(MinIni::minIni PROPERTIES
      IMPORTED_LOCATION "${MinIni_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${MinIni_INCLUDE_DIRS}"
      )
  endif()
endif()
