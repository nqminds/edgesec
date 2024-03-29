cmake_minimum_required(VERSION 3.9.0) # required by FindDoxygen.cmake

# check if Doxygen is installed
if (BUILD_ONLY_DOCS)
  find_package(Doxygen REQUIRED dot)
else ()
  find_package(Doxygen OPTIONAL_COMPONENTS dot)
endif()

if (DOXYGEN_FOUND)
    if (NOT TARGET Doxygen::dot)
        message(
          WARNING
          "dot is not installed, but is highly recommended to create directed graphs"
        )
    endif()

    # Add external library tag files
    include(./doxygen-tag-files)

    # Doxygen parameters
    # currently unused, set if we want to use the `@image` command
    # set(DOXYGEN_IMAGE_PATH "${PROJECT_SOURCE_DIR}/docs")
    # currently unused, set if we want to use the `@dotfile` command
    # set(DOXYGEN_DOTFILE_DIRS "${PROJECT_SOURCE_DIR}/docs")
    # set(DOXYGEN_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/docs")
    set(DOXYGEN_DOT_IMAGE_FORMAT svg)
    set(DOXYGEN_EXTRACT_ALL YES) # document even files missing `@file` command

    set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES) # we only have C-code documentation

    # allows for more complitated include diagrams
    set(DOXYGEN_DOT_GRAPH_MAX_NODES 128)
    set(doxygen_input_files
      "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/docs" "${PROJECT_SOURCE_DIR}/README.md"
    )

    if (BUILD_ONLY_DOCS)
      doxygen_add_docs(doxydocs
        ${doxygen_input_files}
        ALL # part of make all
        COMMENT "Generating API documentation with Doxygen"
      )
    else ()
      doxygen_add_docs(doxydocs
        ${doxygen_input_files}
        COMMENT "Generating API documentation with Doxygen"
      )
    endif()
    add_dependencies(doxydocs ${tag_file_dependencies})
else ()
  message(WARNING "Doxygen need to be installed to generate the doxygen documentation")
endif ()
