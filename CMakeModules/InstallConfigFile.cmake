#[=======================================================================[.rst:
InstallConfigFile.cmake
=======================

Configures and Installs ``config.ini``

Since ``--prefix`` might be changed when running ``cmake --install .``,
we need a custom script to run ``configure_file()`` and that can
point to the actual install locations.

Example
-------

.. code-block:: cmake
install(CODE
"execute_process(
    COMMAND ${CMAKE_COMMAND}
      -D_project_lower=${_project_lower}
      -DCMAKE_INSTALL_LIBDIR=${CMAKE_INSTALL_LIBDIR}
      -Dbuild_dir=${CMAKE_BINARY_DIR}
      -DCMAKE_INSTALL_PREFIX=\${CMAKE_INSTALL_PREFIX} # escape PREFIX so cmake --install --prefix works
      -P ${CMAKE_SOURCE_DIR}/CMakeModules/InstallConfigFile.cmake
  )"
)

#]=======================================================================]
include("${CMAKE_CURRENT_LIST_DIR}/EdgesecInstallLocations.cmake")

foreach(required_var IN ITEMS CMAKE_INSTALL_PREFIX CMAKE_INSTALL_LIBDIR build_dir)
    if(NOT DEFINED ${required_var})
      message(FATAL_ERROR "Variable ${required_var} must be defined (use -D${required_var}=xxxx)")
    endif()
endforeach()

configure_file("config.ini.in" "${build_dir}/config.ini" ESCAPE_QUOTES @ONLY)
file(INSTALL "${build_dir}/config.ini" DESTINATION "${EDGESEC_full_SYSCONFDIR}")
