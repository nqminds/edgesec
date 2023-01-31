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
        URL_HASH SHA512=2343ea488694e3d982a20cde0a2dfe371fc4cf7873f692eaca86f4ba36ad1e082797ad2006450cc0e68c504de689c0d7c12942622e724213782c6887f671512b
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
