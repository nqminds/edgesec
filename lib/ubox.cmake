# Compile libubox
if (USE_UCI_SERVICE AND NOT (BUILD_ONLY_DOCS))
    FetchContent_Declare(
      ubox
      GIT_REPOSITORY https://git.openwrt.org/project/libubox.git
      GIT_SHALLOW true # only download latest commit
      GIT_PROGRESS true # downloading loads of submodules, so we want to see progress
    )
    set(FETCHCONTENT_QUIET OFF)
    SET(BUILD_LUA OFF CACHE INTERNAL "Disable LUA")
    SET(BUILD_EXAMPLES OFF CACHE INTERNAL "Disable Examples")

    FetchContent_MakeAvailable(ubox)
endif ()