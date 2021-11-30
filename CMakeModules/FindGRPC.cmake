#[=======================================================================[.rst:
FindGRPC
--------
Locate and configure the gRPC library.

Defines the following variables:

``GRPC_FOUND``
  Found the GRPC library and header files.
``GRPC_INCLUDE_DIRS``
  Include directories for GRPC.
``GRPC_LIBRARIES``
  The GRPC libraries.

The GRPC version will only be loaded if pkg-config is installed
and can find GRPC:

``GRPC_VERSION``
  The version of the GRPC library. May not always be found.

The following :prop_tgt:`IMPORTED` targets are also defined:

``GRPC::grpc`` - GRPC library
``GRPC::grpc++`` - GRPC C++ library
``GRPC::grpc++_reflection`` - GRPC C++ reflection library
``GRPC::grpc_cpp_plugin`` - C++ generator plugin for Protocol Buffers

#]=======================================================================]
cmake_minimum_required(VERSION 3.13.0)

include(FindPkgConfig)
if (PKG_CONFIG_FOUND)
    pkg_check_modules(GRPC_grpc
        QUIET
        grpc
        IMPORTED_TARGET GLOBAL
    )
    pkg_check_modules(GRPC_grpc++
        QUIET
        grpc++
        IMPORTED_TARGET GLOBAL
    )
endif (PKG_CONFIG_FOUND)

if (GRPC_grpc_FOUND AND GRPC_grpc++_FOUND)
    set(GRPC_INCLUDE_DIR "${GRPC_grpc_INCLUDEDIR}")
    set(GRPC_grpc_LIBRARY "${GRPC_grpc_LINK_LIBRARIES}")
    set(GRPC_grpc++_LIBRARY "${GRPC_grpc++_LINK_LIBRARIES}")
    add_library(GRPC::grpc ALIAS PkgConfig::GRPC_grpc)
    add_library(GRPC::grpc++ ALIAS PkgConfig::GRPC_grpc++)
else (GRPC_grpc_FOUND AND GRPC_grpc++_FOUND)
    # Find GRPC include directory
    find_path(GRPC_INCLUDE_DIR grpc/grpc.h)
    mark_as_advanced(GRPC_INCLUDE_DIR)

    # Find GRPC library
    find_library(GRPC_grpc_LIBRARY NAMES grpc)
    mark_as_advanced(GRPC_grpc_LIBRARY)
    add_library(GRPC::grpc UNKNOWN IMPORTED GLOBAL)
    set_target_properties(GRPC::grpc PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${GRPC_INCLUDE_DIR}
        INTERFACE_LINK_LIBRARIES "-lpthread;-ldl"
        IMPORTED_LOCATION ${GRPC_grpc_LIBRARY}
    )

    # Find GRPC C++ library
    find_library(GRPC_grpc++_LIBRARY NAMES grpc++)
    mark_as_advanced(GRPC_grpc++_LIBRARY)
    add_library(GRPC::grpc++ UNKNOWN IMPORTED GLOBAL)
    set_target_properties(GRPC::grpc++ PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${GRPC_INCLUDE_DIR}
        INTERFACE_LINK_LIBRARIES GRPC::grpc
        IMPORTED_LOCATION ${GRPC_grpc++_LIBRARY}
    )
endif (GRPC_grpc_FOUND AND GRPC_grpc++_FOUND)

# Find GRPC C++ reflection library
find_library(GRPC_GRPC++_REFLECTION_LIBRARY NAMES grpc++_reflection)
mark_as_advanced(GRPC_GRPC++_REFLECTION_LIBRARY)
add_library(GRPC::grpc++_reflection UNKNOWN IMPORTED GLOBAL)
set_target_properties(GRPC::grpc++_reflection PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${GRPC_INCLUDE_DIR}
    INTERFACE_LINK_LIBRARIES GRPC::grpc++
    IMPORTED_LOCATION ${GRPC_GRPC++_REFLECTION_LIBRARY}
)

# Find GRPC CPP generator
find_program(GRPC_CPP_PLUGIN NAMES grpc_cpp_plugin)
mark_as_advanced(GRPC_CPP_PLUGIN)
add_executable(GRPC::grpc_cpp_plugin IMPORTED GLOBAL)
set_target_properties(GRPC::grpc_cpp_plugin PROPERTIES
    IMPORTED_LOCATION ${GRPC_CPP_PLUGIN}
)

# need to use grpc++ version, not grpc version
# Might be null if there is no pkg-config version
set(GRPC_VERSION ${GRPC_grpc++_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GRPC
    REQUIRED_VARS GRPC_INCLUDE_DIR GRPC_grpc_LIBRARY GRPC_grpc++_LIBRARY GRPC_GRPC++_REFLECTION_LIBRARY GRPC_CPP_PLUGIN
    VERSION_VAR GRPC_VERSION # may be empty
)

set(GRPC_LOCAL_INSTALL_WARNING_MESSAGE "\
Found GRPC++ library in /usr/local. \
This may cause issues unless you've also installed a compatible protobuf version. \
WE RECOMMEND INSTALLING GRPC FROM YOUR SYSTEM LIBRARIES INSTEAD. \
(e.g. using `apt install libgrpc-dev`)
")

if(GRPC_FOUND)
    set(GRPC_LIBRARIES GRPC::grpc GRPC::grpc++ GRPC::grpc++_reflection)
    set(GRPC_INCLUDE_DIRS ${GRPC_INCLUDE_DIR})

    string(FIND "${GRPC_grpc++_LIBRARY}" "/usr/local" "grpc++_lib_in_usr_local")
    if (${grpc++_lib_in_usr_local} EQUAL -1)
        message(WARNING ${GRPC_LOCAL_INSTALL_WARNING_MESSAGE})
    endif()
endif(GRPC_FOUND)
