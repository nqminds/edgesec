# Compile libubox
if (USE_UCI_SERVICE AND NOT (BUILD_ONLY_DOCS))
    add_compile_definitions(WITH_UCI_SERVICE)
    set(LIBUBOX_INSTALL_ROOT ${CMAKE_CURRENT_BINARY_DIR}/lib)
    set(LIBUBOX_INSTALL_DIR ${LIBUBOX_INSTALL_ROOT}/ubox)
    set(LIBUBOX_INCLUDE_PATH ${LIBUBOX_INSTALL_DIR}/include)
    set(LIBUBOX_LIB_DIR "${LIBUBOX_INSTALL_DIR}/lib")

    find_library(LIBUBOX_LIB NAMES libubox.so ubox PATHS "${LIBUBOX_LIB_DIR}" NO_DEFAULT_PATH)
    find_library(LIBUBOX_STATIC_LIB NAMES libubox.a ubox PATHS "${LIBUBOX_LIB_DIR}" NO_DEFAULT_PATH)

    if (LIBUBOX_LIB AND LIBUBOX_STATIC_LIB)
      message("Found shared libubox library: ${LIBUBOX_LIB}")
      message("Found static libubox library: ${LIBUBOX_STATIC_LIB}")
    else ()
      FetchContent_Declare(
        libubox
        GIT_REPOSITORY https://git.openwrt.org/project/libubox.git
        GIT_TAG f2d6752901f2f2d8612fb43e10061570c9198af1 # master as of 2022-02-10
        GIT_PROGRESS true
      )
      FetchContent_Populate(libubox)

      execute_process(COMMAND
        bash
        ${CMAKE_SOURCE_DIR}/lib/compile_ubox.sh
        ${libubox_SOURCE_DIR}
        ${LIBUBOX_INSTALL_DIR}
        ${CMAKE_SYSTEM_NAME}
        ${CMAKE_SYSTEM_PROCESSOR}
        ${CMAKE_C_COMPILER}
      )

      find_library(LIBUBOX_LIB NAMES libubox.so ubox PATHS "${LIBUBOX_LIB_DIR}" NO_DEFAULT_PATH)
      find_library(LIBUBOX_STATIC_LIB NAMES libubox.a ubox PATHS "${LIBUBOX_LIB_DIR}" NO_DEFAULT_PATH)
    endif ()

    set(LIBUCI_INSTALL_ROOT ${CMAKE_CURRENT_BINARY_DIR}/lib)
    set(LIBUCI_INSTALL_DIR ${LIBUCI_INSTALL_ROOT}/uci)
    set(LIBUCI_INCLUDE_PATH ${LIBUCI_INSTALL_DIR}/include)
    set(LIBUCI_LIB_DIR "${LIBUCI_INSTALL_DIR}/lib")

    ExternalProject_Add(
      libuci
      GIT_REPOSITORY https://git.openwrt.org/project/uci.git
      GIT_TAG f84f49f00fb70364f58b4cce72f1796a7190d370 # master as of 2021-10-22
      GIT_PROGRESS true
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

    add_library(OpenWRT::LIBUCI SHARED IMPORTED)
    file(MAKE_DIRECTORY "${LIBUCI_INCLUDE_PATH}")
    set_target_properties(OpenWRT::LIBUCI PROPERTIES
      IMPORTED_LOCATION "${LIBUCI_LIB_DIR}/libuci.so"
      INTERFACE_INCLUDE_DIRECTORIES "${LIBUCI_INCLUDE_PATH}"
    )
    # tell cmake that we can only use OpenWRT::LIBUCI after we compile it
    add_dependencies(OpenWRT::LIBUCI libuci)
    target_link_libraries(OpenWRT::LIBUCI INTERFACE "${LIBUBOX_LIB}")
endif ()
