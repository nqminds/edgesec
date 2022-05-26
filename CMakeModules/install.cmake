include(GNUInstallDirs) # automagically setup install dir locations
install(
  TARGETS edgesec
  RUNTIME
)

if (USE_MDNS_SERVICE AND BUILD_PCAP_LIB)
  install(
    TARGETS mdnsf
    RUNTIME
  )
endif ()

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

get_filename_component(EDGESEC_cert_directory ${EDGESEC_cert_location} DIRECTORY)
get_filename_component(EDGESEC_cert_filename ${EDGESEC_cert_location} NAME)
install(FILES "${CMAKE_SOURCE_DIR}/deployment/rpi-config/CA.pem" DESTINATION "${EDGESEC_cert_directory}" RENAME "${EDGESEC_cert_filename}")

# for install /lib directories, we need to add a trailing "/" to avoid
# installing into ${EDGESEC_private_lib_dir}/lib
if (BUILD_UUID_LIB AND LIBUUID_LIB)
    install(DIRECTORY "${LIBUUID_LIB_DIR}/" DESTINATION ${EDGESEC_private_lib_dir} PATTERN "*.la" EXCLUDE)
endif ()

if (BUILD_SQLITE_LIB AND LIBSQLITE_LIB)
  install(DIRECTORY "${LIBSQLITE_LIB_DIR}/" DESTINATION ${EDGESEC_private_lib_dir} PATTERN "*.la" EXCLUDE)
endif ()

if(BUILD_PCAP_LIB AND LIBPCAP_LIB)
  install(DIRECTORY "${LIBPCAP_LIB_DIR}/" DESTINATION ${EDGESEC_private_lib_dir})
endif ()

if(BUILD_OPENSSL_LIB AND LIBCRYPTO_LIB)
  install(DIRECTORY "${LIBOPENSSL_LIB_PATH}/" DESTINATION ${EDGESEC_private_lib_dir})
endif ()

if (BUILD_NETLINK_LIB AND LIBNETLINK_LIB)
  install(DIRECTORY "${LIBNETLINK_LIB_PATH}/" DESTINATION ${EDGESEC_private_lib_dir})
endif ()

if (BUILD_MNL_LIB AND MNL_FOUND)
  get_filename_component(MNL_LIBRARY_DIR ${MNL_LIBRARY} DIRECTORY)
  install(DIRECTORY ${MNL_LIBRARY_DIR}/ DESTINATION ${EDGESEC_private_lib_dir} PATTERN "*.la" EXCLUDE)
endif ()

if (BUILD_HOSTAPD AND HOSTAPD)
  install(PROGRAMS ${HOSTAPD} DESTINATION ${EDGESEC_libexec_dir})
endif ()
