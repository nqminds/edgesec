include(FetchContent)

if (BUILD_ONLY_DOCS)
    # pass
else ()
    FetchContent_Declare(
        sha256_download
        URL https://github.com/amosnier/sha-2/archive/5e6011c6a8750110fb4607d71087ae7af90b558b.tar.gz
        URL_HASH SHA512=9143c06844059e364e0228745d9b3c934d204680b41ef992d791faf33c038368146080ee22a7f508559fe975118914bbcbb6a9c636832ec7bd06fceec8d76f35
    )
    FetchContent_Populate(sha256_download)

    add_library(sha256 OBJECT "${sha256_download_SOURCE_DIR}/sha-256.c")
    target_include_directories(sha256 PUBLIC "${sha256_download_SOURCE_DIR}")
endif ()
