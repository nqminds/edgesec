# Compile library libnetlink
if (BUILD_NL_LIB AND NOT (BUILD_ONLY_DOCS))
  find_path(LIBNL_INCLUDE_DIR netlink/netlink.h
  	/usr/include
  	/usr/include/libnl3
  	/usr/local/include
  	/usr/local/include/libnl3
  )

  find_library(LIBNL_LIBRARY NAMES nl nl-3)
  # find_library(LibNL_ROUTE_LIBRARY NAMES nl-route nl-route-3)
  # find_library(LibNL_NETFILTER_LIBRARY NAMES nl-nf nl-nf-3)
  find_library(LIBNL_GENL_LIBRARY NAMES nl-genl nl-genl-3)

  if (LIBNL_INCLUDE_DIR AND LIBNL_LIBRARY)
    message("Found netlink library: ${LIBNL_LIBRARY}")
    # message("Found netlink route library: ${LibNL_ROUTE_LIBRARY}")
    # message("Found netlink netfilter library: ${LibNL_NETFILTER_LIBRARY}")
    message("Found netlink genl library: ${LIBNL_GENL_LIBRARY}")
    message("Found netlink includes: ${LIBNL_INCLUDE_DIR}")
  ELSE ()
  	message("Netlink version 3 development packages cannot be found.")
  	message("In Debian/Ubuntu, they may be called:")
  	message("libnl-3-dev libnl-genl-3dev libnl-nf-3-dev libnl-route-3-dev")
  	message(FATAL_ERROR "Could not find netlink library.")
  endif ()
endif ()
