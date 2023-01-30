if (BUILD_ONLY_DOCS)
    # pass
else ()
    # it's possible to find uthash on Ubuntu/Debian repos, but it's a tiny
    # download, so we might as well download it

    # this version removes the strdup requirement for better ISO C compatibility
    set(UTHASH_VERSION 85bf75ab7189858f97b83a90a1426a1d5420d2d6)
    FetchContent_Declare(
        uthash
        URL "https://api.github.com/repos/troydhanson/uthash/tarball/${UTHASH_VERSION}"
        URL_HASH SHA512=0f67b2842ceecb7d59d5538a89cf25e198cf14e009d5d6141839dd3aea241bd9a1529d5eb87eed0468dbf4478d9db0ef9096f5826f32d512b96e3edd2b19e41a
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
