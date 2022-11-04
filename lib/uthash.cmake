if (BUILD_ONLY_DOCS)
    # pass
else ()
    # it's possible to find uthash on Ubuntu/Debian repos, but it's a tiny
    # download, so we might as well download it
    set(UTHASH_VERSION 2.1.0)
    FetchContent_Declare(
        uthash
        URL "https://github.com/troydhanson/uthash/archive/refs/tags/v${UTHASH_VERSION}.tar.gz"
        URL_HASH SHA512=c8005113a48ec7636715ecec0286a5d9086971a7267947aba9e0ad031b6113a4f38a1fb512d33d6fefb5891635fdd31169ce4d6ab04b938bda612ebbccb3eda0
        DOWNLOAD_NAME "uthash-${UTHASH_VERSION}.tar.gz"
        DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
    )
    FetchContent_MakeAvailable(uthash)
    set(UTHASH_INCLUDE_DIR "${uthash_SOURCE_DIR}/include")
    file(MAKE_DIRECTORY "${UTHASH_INCLUDE_DIR}")

    # Could import libut for static lib (see https://github.com/troydhanson/libut)
    # but easier to leave as header-only lib
    add_library(LibUTHash::LibUTHash INTERFACE IMPORTED)
    target_include_directories(LibUTHash::LibUTHash INTERFACE "${UTHASH_INCLUDE_DIR}")
    add_dependencies(LibUTHash::LibUTHash uthash)
endif ()
