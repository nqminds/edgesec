include(GNUInstallDirs) # automagically setup install dir locations
install(
  TARGETS edgesec capsrv
  RUNTIME
)
if (BUILD_REST_SERVER AND LIBMICROHTTPD_LIB)
  install(
    TARGETS restsrv
    RUNTIME
  )
endif ()
if (BUILD_SQLSYNC_SERVICE AND LIBSQLITE_LIB)
  install(
    TARGETS sqlsyncsrv
    RUNTIME
  )
endif ()
if (BUILD_REVERSE_SERVICE)
  install(
    TARGETS revclient revsrv
    RUNTIME
  )
endif ()

# usually /usr/local/lib/edgesec (or /usr/lib/edgesec for .deb)
# EDGESEC_private_lib_dir is set in main CMakeLists.txt, as we need it to set RPATH before targets
# currently only hostapd, so it doesn't conflict with other hostapds
set(EDGESEC_libexec_dir "${CMAKE_INSTALL_FULL_LIBEXECDIR}/${_project_lower}" CACHE PATH "Directory of private EDGESec bins")
set(EDGESEC_config_dir "${CMAKE_INSTALL_FULL_SYSCONFDIR}/${_project_lower}" CACHE PATH "Directory of EDGESec config files")
set(EDGESEC_log_dir "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/log/${_project_lower}" CACHE PATH "Directory of EDGESec log files")
set(EDGESEC_local_lib_dir "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/lib/${_project_lower}" CACHE PATH "Directory of EDGESec persistant files (e.g. databases)")
set(EDGESEC_runstate_dir "${CMAKE_INSTALL_FULL_RUNSTATEDIR}/${_project_lower}" CACHE PATH "Directory of EDGESec run-state files (.pid and socket files)")

set(EDGESEC_cert_location "${EDGESEC_config_dir}/CA/CA.pem" CACHE FILEPATH "Path to edgesec certificate authority file")
configure_file(
  "config.ini.in"
  "${PROJECT_BINARY_DIR}/config.ini"
  ESCAPE_QUOTES # values are quoted, so we need to escape quotes
  @ONLY # we only use @VAR_NAME@ syntax
)

# /etc/edgesec/config.ini folder
install(FILES "${PROJECT_BINARY_DIR}/config.ini" DESTINATION "${EDGESEC_config_dir}")
get_filename_component(EDGESEC_cert_directory ${EDGESEC_cert_location} DIRECTORY)
get_filename_component(EDGESEC_cert_filename ${EDGESEC_cert_location} NAME)
install(FILES "${CMAKE_SOURCE_DIR}/scripts/deployments/rpi/CA.pem" DESTINATION "${EDGESEC_cert_directory}" RENAME "${EDGESEC_cert_filename}")

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

if (BUILD_NDPI_LIB AND LIBNDPI_LIB)
  install(DIRECTORY "${LIBNDPI_LIB_DIR}/" DESTINATION ${EDGESEC_private_lib_dir})
endif ()

if (BUILD_MNL_LIB AND MNL_FOUND)
  get_filename_component(MNL_LIBRARY_DIR ${MNL_LIBRARY} DIRECTORY)
  install(DIRECTORY ${MNL_LIBRARY_DIR}/ DESTINATION ${EDGESEC_private_lib_dir} PATTERN "*.la" EXCLUDE)
endif ()

if (BUILD_MICROHTTPD_LIB AND LIBMICROHTTPD_LIB)
  install(DIRECTORY "${LIBMICROHTTPD_LIB_DIR}/" DESTINATION ${EDGESEC_private_lib_dir} PATTERN "*.la" EXCLUDE)
endif ()

if (BUILD_GRPC_LIB AND LIBGRPC_LIB)
  install(DIRECTORY "${LIBGRPC_LIB_DIR}/" DESTINATION ${EDGESEC_private_lib_dir})
endif ()

if (BUILD_HOSTAPD AND HOSTAPD)
  install(PROGRAMS ${HOSTAPD} DESTINATION ${EDGESEC_libexec_dir})
endif ()
