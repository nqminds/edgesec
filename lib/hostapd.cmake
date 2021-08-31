# Find the hostapd program
if (BUILD_HOSTAPD AND NOT (BUILD_ONLY_DOCS))
  include(ExternalProject)

  ExternalProject_Add(hostapd
    URL https://w1.fi/releases/hostapd-2.9.tar.gz
    CONFIGURE_COMMAND ""
  )

  if (FALSE)
    set(HOSTAPD_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/hostap/hostapd")
    set(HOSTAPD_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}")
    find_program(HOSTAPD NAMES hostapd PATHS "${HOSTAPD_INSTALL_DIR}")
    if (HOSTAPD)
      message("Found hostapd program: ${HOSTAPD}")
    ELSE ()
      message("Building hostapd...")
      execute_process(
        COMMAND make
        WORKING_DIRECTORY "${HOSTAPD_SOURCE_DIR}"
      )
      execute_process(
        COMMAND cp ./hostapd "${HOSTAPD_INSTALL_DIR}"
        WORKING_DIRECTORY "${HOSTAPD_SOURCE_DIR}"
      )
      execute_process(
        COMMAND make clean
        WORKING_DIRECTORY "${HOSTAPD_SOURCE_DIR}"
      )
      find_program(HOSTAPD NAMES hostapd PATHS "${HOSTAPD_INSTALL_DIR}")
    endif ()
  endif()
endif ()

