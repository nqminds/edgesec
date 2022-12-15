include(GNUInstallDirs) # automagically setup install dir locations
install(
  TARGETS edgesec edgesec-recap
  RUNTIME
)

# usually /usr/local/lib/edgesec (or /usr/lib/edgesec for .deb)
# EDGESEC_private_lib_dir is set in main CMakeLists.txt, as we need it to set RPATH before targets
# currently only hostapd, so it doesn't conflict with other hostapds
configure_file(
  "config.ini.in"
  "config.ini"
  ESCAPE_QUOTES # values are quoted, so we need to escape quotes
  @ONLY # we only use @VAR_NAME@ syntax
)
configure_file(config.ini.in config.ini.in COPYONLY)

# /etc/edgesec/config.ini folder
# runs configure_file again and install config.ini.in
# install(SCRIPT "./CMakeModules/InstallConfigFile.cmake")
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

# for install /lib directories, we need to add a trailing "/" to avoid
# installing into ${EDGESEC_private_lib_dir}/lib
if (BUILD_UUID_LIB AND LIBUUID_LIB)
    install(DIRECTORY "${LIBUUID_LIB_DIR}/" DESTINATION ${EDGESEC_private_lib_dir} PATTERN "*.la" EXCLUDE)
endif ()

if (BUILD_SQLITE_LIB AND TARGET SQLite::SQLite3 AND LIBSQLITE_LIB_DIR)
  get_target_property(SQLite3_type SQLite::SQLite3 TYPE)
  if(SQLite3_type STREQUAL STATIC_LIBRARY)
    # don't bother installing static libs
  else()
    install(DIRECTORY "${LIBSQLITE_LIB_DIR}/" DESTINATION ${EDGESEC_private_lib_dir} PATTERN "*.la" EXCLUDE)
  endif()
endif ()

if(BUILD_OPENSSL3_LIB AND LIBCRYPTO_LIB AND LIBOPENSSL_LIB_PATH)
  install(DIRECTORY "${LIBOPENSSL_LIB_PATH}/" DESTINATION ${EDGESEC_private_lib_dir})
endif ()

if (BUILD_MNL_LIB AND TARGET MNL::mnl AND MNL_LIBRARY)
  get_filename_component(MNL_LIBRARY_DIR ${MNL_LIBRARY} DIRECTORY)
  install(DIRECTORY ${MNL_LIBRARY_DIR}/ DESTINATION ${EDGESEC_private_lib_dir} PATTERN "*.la" EXCLUDE)
endif ()

if (BUILD_HOSTAPD AND HOSTAPD)
  install(PROGRAMS ${HOSTAPD} DESTINATION ${EDGESEC_libexec_dir})
endif ()
