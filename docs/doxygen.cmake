# check if Doxygen is installed
find_package(Doxygen)

if (DOXYGEN_FOUND)
    # set input and output files
    set(DOXYGEN_IN Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    # Doxygen.in file parameters
    set(DOXYGEN_INPUT "src docs")
    set(DOXYGEN_IMAGE_PATH docs)
    set(DOXYGEN_DOTFILE_DIRS docs)
    set(DOXYGEN_OUTPUT_DIRECTORY docs)
    # request to configure the file
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
    message("Doxygen build started")

    # note the option ALL which allows to build the docs together with the application
    add_custom_target( doxydocs COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )
else ()
  message(WARNING "Doxygen need to be installed to generate the doxygen documentation")
endif ()
