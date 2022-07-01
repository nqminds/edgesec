#[=======================================================================[.rst:
EdgesecInstallLocations
-----------------------

Defines locations to install EDGESEC files

This is a seperate file from the rest of the CMake config files,
so it can be used both during:
- configure step (e.g. cmake ..)
- install step (e.g. cmake --install ..)

We can't use the default cmake `install()` syntax, since we need to know
the absolute paths to put as default vals in the `config.ini` file


Result Variables
^^^^^^^^^^^^^^^^

Including this module defines the following values:

``EDGESEC_<path_name>``
  Relative path to install/configure the given type of files.

``EDGESEC_<path_name>``

  Absolute path to install/configure the given type of files.
  This should be used when embedding the location in a ``config.ini`` file.

where ``path_name`` is one of:

``bin_dir``
  Directory to install EDGESec user binaries, (``/usr/bin``)
``private_lib_dir``
  Directory to install EDGESec private shared library files (``/usr/lib/edgesec``)
  These are designed for use with EDGESec only, and may conflict with other OS
  shared library files.
``libexec_dir``
  Directory of private EDGESec binaries/executables (``/usr/libexec/edgesec``)
  These are designed for use with EDGESec only, and may conflict with other OS
  binaries (e.g. ``hostapd``)
``config_dir``
  Directory of EDGESec config files, (``/etc/edgesec``)
``log_dir``
  Directory of EDGESec log files, (``/var/log/edgesec``)
``local_lib_dir``
  Directory of EDGESec persistant files (e.g. databases), (``/var/lib/edgesec``)
``runstate_dir``
  Directory of EDGESec run-state files (.pid and socket files), (``/var/run/edgesec``)
#]=======================================================================]

cmake_minimum_required(VERSION 3.7.0)

foreach(required_var IN ITEMS _project_lower CMAKE_INSTALL_PREFIX)
    if(NOT DEFINED ${required_var})
      message(FATAL_ERROR "Variable ${required_var} must be defined")
    endif()
endforeach()

include(GNUInstallDirs)

# creates the vars:
# - EDGESEC_${PATH_NAME}: relative path
# - EDGESEC_full_${PATH_NAME}: absolute path
macro(_create_edgesec_path PATH_NAME PATH TYPE)
    set(EDGESEC_${PATH_NAME} ${PATH})
    set(dir ${TYPE}) # not needed in CMake 3.20+
    GNUInstallDirs_get_absolute_install_dir(EDGESEC_full_${PATH_NAME} EDGESEC_${PATH_NAME} ${TYPE})
endmacro()

_create_edgesec_path(bin_dir "${CMAKE_INSTALL_BINDIR}" BIN)
# Directory for private EDGESec shared libs (*.so files)
_create_edgesec_path(private_lib_dir "${CMAKE_INSTALL_LIBDIR}/${_project_lower}" LIB)
# Directory of private EDGESec binaries/executables
_create_edgesec_path(libexec_dir "${CMAKE_INSTALL_LIBEXECDIR}/${_project_lower}" LIBEXECDIR)
# Directory of EDGESec config files
_create_edgesec_path(config_dir "${CMAKE_INSTALL_SYSCONFDIR}/${_project_lower}" SYSCONFDIR)
# Directory of EDGESec log files
_create_edgesec_path(log_dir "${CMAKE_INSTALL_LOCALSTATEDIR}/log/${_project_lower}" LOCALSTATEDIR)
# Directory of EDGESec persistant files (e.g. databases)
_create_edgesec_path(local_lib_dir "${CMAKE_INSTALL_LOCALSTATEDIR}/lib/${_project_lower}" LOCALSTATEDIR)
# Directory of EDGESec run-state files (.pid and socket files)
_create_edgesec_path(runstate_dir "${CMAKE_INSTALL_RUNSTATEDIR}/${_project_lower}" RUNSTATEDIR)
