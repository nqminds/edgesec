# Defines locations to install files
# Needs to be placed in a seperate file
# so it can be used both during:
# - configure step (e.g. cmake ..)
# - install step (e.g. cmake --install ..)
cmake_minimum_required(VERSION 3.7.0)

foreach(required_var IN ITEMS _project_lower CMAKE_INSTALL_PREFIX)
    if(NOT DEFINED ${required_var})
      message(FATAL_ERROR "Variable ${required_var} must be defined")
    endif()
endforeach()

include(GNUInstallDirs)

set(EDGESEC_bin_dir "${CMAKE_INSTALL_BINDIR}")
set(EDGESEC_private_lib_dir "${CMAKE_INSTALL_LIBDIR}/${_project_lower}") # CACHE PATH "Directory of private EDGESec shared libs")
set(EDGESEC_libexec_dir "${CMAKE_INSTALL_LIBEXECDIR}/${_project_lower}") # CACHE PATH "Directory of private EDGESec bins")
set(EDGESEC_config_dir "${CMAKE_INSTALL_SYSCONFDIR}/${_project_lower}") # CACHE PATH "Directory of EDGESec config files")
set(EDGESEC_log_dir "${CMAKE_INSTALL_LOCALSTATEDIR}/log/${_project_lower}") # CACHE PATH "Directory of EDGESec log files")
set(EDGESEC_local_lib_dir "${CMAKE_INSTALL_LOCALSTATEDIR}/lib/${_project_lower}") # CACHE PATH "Directory of EDGESec persistant files (e.g. databases)")
set(EDGESEC_runstate_dir "${CMAKE_INSTALL_RUNSTATEDIR}/${_project_lower}") # CACHE PATH "Directory of EDGESec run-state files (.pid and socket files)")
set(EDGESEC_cert_location "${EDGESEC_config_dir}/CA/CA.pem") # CACHE FILEPATH "Path to edgesec certificate authority file")

# Only needed for EDGESEC_full_bin_dir since CMAKE_FULL_INSTALL_BINDIR does not include DESTDIR
# This is to add the actual path into config.ini

# absolute paths! Required by config.ini
# makes dirs like EDGESEC_full_libexec_dir
foreach(dir in private_lib_dir libexec_dir config_dir log_dir local_lib_dir runstate_dir cert_location)
    GNUInstallDirs_get_absolute_install_dir(
        EDGESEC_full_${dir} EDGESEC_${dir} ${dir}
    )
    # FULL_PATH isn't actually always absolute due to destdir
    set(with_destdir "$ENV{DESTDIR}${EDGESEC_full_${dir}}")
    if (NOT IS_ABSOLUTE "${with_destdir}")
        # make paths in config.ini absolute, so we can call them from different working dir
        get_filename_component(with_destdir
            "${with_destdir}"
            ABSOLUTE)
    endif()
    set(EDGESEC_full_${dir} "${with_destdir}")
endforeach()

message("CMAKE_INSTALL_PREFIX is ${CMAKE_INSTALL_PREFIX}")
message("EDGESEC_full_libexec_dir is ${EDGESEC_full_libexec_dir}")
