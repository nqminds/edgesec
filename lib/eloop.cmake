if (NOT (BUILD_ONLY_DOCS))
    include(FetchContent)

    # To generate or modify these patch files, do:
    # cd "${eloop_download_SOURCE_DIR}"
    # git init
    # git add . && git commit -m "initial commit"
    # git am ~/edgesec/lib/eloop/patches/*.patch
    #
    # Then you can use `git rebase` to modify your git history.
    # When done, do `git format-patch <FIRST_COMMID_ID>` to remake the patches
    file(GLOB eloop_patches CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/lib/eloop/patches/*.patch")

    function(cat IN_FILE OUT_FILE)
        file(READ ${IN_FILE} CONTENTS)
        file(APPEND ${OUT_FILE} "${CONTENTS}")
    endfunction()

    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/eloop_patches_combined.patch" "")
    list(SORT eloop_patches)
    foreach(eloop_patch ${eloop_patches})
        cat("${eloop_patch}" "${CMAKE_CURRENT_BINARY_DIR}/eloop_patches_combined.patch")
    endforeach()

    # this is the same download as `hostapd.cmake`, but with a custom patch step
    FetchContent_Declare(
        eloop_download
        URL https://w1.fi/releases/hostapd-2.10.tar.gz
        URL_HASH SHA512=243baa82d621f859d2507d8d5beb0ebda15a75548a62451dc9bca42717dcc8607adac49b354919a41d8257d16d07ac7268203a79750db0cfb34b51f80ff1ce8f
        PATCH_COMMAND
            patch -p1 -d "<SOURCE_DIR>" -i "${CMAKE_CURRENT_BINARY_DIR}/eloop_patches_combined.patch"
    )
    FetchContent_Populate(eloop_download)

    add_library(eloop STATIC "${eloop_download_SOURCE_DIR}/src/utils/eloop.c")
    target_link_libraries(eloop PUBLIC allocs os eloop::list PRIVATE log)
    # so that eloop.h will be included.
    target_include_directories(eloop
        PUBLIC "${eloop_download_SOURCE_DIR}/src/utils" "${CMAKE_SOURCE_DIR}"
    )

    if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
        # include <sys/epoll.h> (Linux/glibc only)
        target_compile_definitions(eloop PUBLIC CONFIG_ELOOP_EPOLL)

        # include <sys/event.h> (FreeBSD?)
        # target_compile_definitions(eloop PUBLIC CONFIG_ELOOP_KQUEUE)

        # include <poll.h>
        # target_compile_definitions(eloop PUBLIC CONFIG_ELOOP_POLL)

        # Default: use basic slow select()
        # target_compile_definitions(eloop PUBLIC CONFIG_ELOOP_SELECT)
    endif()

    add_library(eloop::eloop ALIAS eloop)

    add_library(eloop::list INTERFACE IMPORTED)
    target_include_directories(eloop::list INTERFACE "${eloop_download_SOURCE_DIR}/src/utils")
endif()
