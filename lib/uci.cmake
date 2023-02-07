# Compile libubox
if (USE_UCI_SERVICE AND NOT (BUILD_ONLY_DOCS))
  if (NOT BUILD_UCI_LIB)
    find_package(UCI MODULE REQUIRED)
    message("Found libuci library: ${UCI_LIBRARIES}")
  else()
    set(LIBUBOX_INSTALL_ROOT ${CMAKE_CURRENT_BINARY_DIR}/lib)
    set(LIBUBOX_INSTALL_DIR ${LIBUBOX_INSTALL_ROOT}/ubox)
    set(LIBUBOX_INCLUDE_PATH ${LIBUBOX_INSTALL_DIR}/include)
    set(LIBUBOX_LIB_DIR "${LIBUBOX_INSTALL_DIR}/lib")

    set(libubox_git_tag f2d6752901f2f2d8612fb43e10061570c9198af1) # master as of 2022-02-10
    ExternalProject_Add(
      libubox
      #GIT_REPOSITORY https://git.openwrt.org/project/libubox.git
      #GIT_TAG "${libubox_git_tag}"
      # Escape semicolons in gitweb URL with `\\\;`
      URL "https://git.openwrt.org/?p=project/libubox.git\\\;a=snapshot\\\;h=${libubox_git_tag}\\\;sf=tgz"
      # this hash will change when OpenWRT's git server updates to v2.38.0+
      URL_HASH SHA3_256=2189a3dbe55095e1a53c20aeb48d0d40b4fe8ea6f85a85653899bae63209cd5c
      DOWNLOAD_NAME "libubox-${libubox_git_tag}.tar.gz"
      DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
      INSTALL_DIR "${LIBUBOX_INSTALL_DIR}"
      CMAKE_ARGS
        -DBUILD_LUA=OFF
        -DBUILD_EXAMPLES=OFF
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        # need to pass cross-compile toolchain manually
        -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
        -DCMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    )
    set(LIBUBOX_LIB "${LIBUBOX_LIB_DIR}/libubox.so")
    set(LIBUBOX_STATIC_LIB "${LIBUBOX_LIB_DIR}/libubox.a")

    set(LIBUCI_INSTALL_ROOT ${CMAKE_CURRENT_BINARY_DIR}/lib)
    set(LIBUCI_INSTALL_DIR ${LIBUCI_INSTALL_ROOT}/uci)
    set(LIBUCI_INCLUDE_PATH ${LIBUCI_INSTALL_DIR}/include)
    set(LIBUCI_LIB_DIR "${LIBUCI_INSTALL_DIR}/lib")

    set(libuci_git_tag f84f49f00fb70364f58b4cce72f1796a7190d370) # master as of 2021-10-22
    ExternalProject_Add(
      libuci
      #GIT_REPOSITORY https://git.openwrt.org/project/uci.git
      #GIT_TAG "${libuci_git_tag}"
      # Escape semicolons in gitweb URL with `\\\;`
      URL "https://git.openwrt.org/?p=project/uci.git\\\;a=snapshot\\\;h=${libuci_git_tag}\\\;sf=tgz"
      # this hash will change when OpenWRT's git server updates to v2.38.0+
      URL_HASH SHA3_256=4524e6d408204e9a3f3e5a3531888d4e45fdf617a3aceb1a2e271e262f0fd3bd
      DOWNLOAD_NAME "uci-${libuci_git_tag}.tar.gz"
      DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
      INSTALL_DIR "${LIBUCI_INSTALL_DIR}"
      CMAKE_ARGS
        -DBUILD_LUA=OFF
        # https://git.openwrt.org/?p=project/uci.git;a=blob;f=CMakeLists.txt;h=50e7f51fe5fafa9052c125d54443a8b31599efb6;hb=HEAD#l81-85
        # libuci does not install the static lib when running `make install`
        # -DBUILD_STATIC=ON
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -Dubox_include_dir=${LIBUBOX_INCLUDE_PATH}
        -Dubox=${LIBUBOX_LIB}
        -Dubox-static=${LIBUBOX_STATIC_LIB}
        # need to pass cross-compile toolchain manually
        -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
        -DCMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    )
    # LibUBOX must be installed for LibUCI to configure properly
    ExternalProject_Add_StepDependencies(libuci configure libubox)

    add_library(OpenWRT::UCI SHARED IMPORTED)
    file(MAKE_DIRECTORY "${LIBUCI_INCLUDE_PATH}")
    set_target_properties(OpenWRT::UCI PROPERTIES
      IMPORTED_LOCATION "${LIBUCI_LIB_DIR}/libuci.so"
      INTERFACE_INCLUDE_DIRECTORIES "${LIBUCI_INCLUDE_PATH}"
    )
    # tell cmake that we can only use OpenWRT::UCI after we compile it
    add_dependencies(OpenWRT::UCI libuci)
    target_link_libraries(OpenWRT::UCI INTERFACE "${LIBUBOX_LIB}")
  endif()
endif ()
