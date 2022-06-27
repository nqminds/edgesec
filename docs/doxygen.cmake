cmake_minimum_required(VERSION 3.9.0) # required by FindDoxygen.cmake

# check if Doxygen is installed
find_package(Doxygen OPTIONAL_COMPONENTS dot)

if (DOXYGEN_FOUND)
    if (NOT DEFINED Doxygen::dot)
        message(
          WARNING
          "dot is not installed, but is highly recommended to create directed graphs"
        )
    endif()
    # Doxygen parameters
    # currently unused, set if we want to use the `@image` command
    # set(DOXYGEN_IMAGE_PATH "${PROJECT_SOURCE_DIR}/docs")
    # currently unused, set if we want to use the `@dotfile` command
    # set(DOXYGEN_DOTFILE_DIRS "${PROJECT_SOURCE_DIR}/docs")
    set(DOXYGEN_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/docs")
    # the docusaurus folder has a node_modules folder, which is a bunch of mess
    set(DOXYGEN_EXCLUDE_PATTERNS "${PROJECT_SOURCE_DIR}/docs/docusaurus")

    set(DOXYGEN_PROJECT_NAME "edgesec") # defaults to EDGESEC
    set(DOXYGEN_EXTRACT_ALL YES) # document even files missing `@file` command

    # note the option ALL which allows to build the docs together with the application
    doxygen_add_docs(doxydocs
      "${PROJECT_SOURCE_DIR}/src" ${PROJECT_SOURCE_DIR}/docs
      # ALL
      COMMENT "Generating API documentation with Doxygen"
    )
else ()
  message(WARNING "Doxygen need to be installed to generate the doxygen documentation")
endif ()
