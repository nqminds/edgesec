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
set(EDGESEC_private_lib_dir "${CMAKE_INSTALL_LIBDIR}/${_project_lower}" CACHE PATH "Path to where private EDGESec shared libs are stored")
# currently only hostapd, so it doesn't conflict with other hostapds
set(EDGESEC_libexec_dir "${CMAKE_INSTALL_FULL_LIBEXECDIR}/${_project_lower}" CACHE PATH "Path to where private EDGESec bins are stored")

# /etc/edgesec/config.ini folder
install(FILES "${PROJECT_BINARY_DIR}/config.ini" DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/${_project_lower}")

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

if (BUILD_MNL_LIB AND LIBMNL_LIB)
  install(DIRECTORY "${LIBMNL_LIB_DIR}/" DESTINATION ${EDGESEC_private_lib_dir} PATTERN "*.la" EXCLUDE)
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
