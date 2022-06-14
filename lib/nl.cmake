# Find library libnl-3
if (USE_NETLINK_SERVICE AND NOT (BUILD_ONLY_DOCS))
  find_package(NL REQUIRED COMPONENTS core genl)
endif ()
