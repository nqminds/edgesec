# Downloads Doxygen tagfiles
#
# These are used to auto-link EDGESec docs to external library
# docs.
#

include(ExternalProject)

ExternalProject_Add(
    cppreference_tag_file
    URL https://upload.cppreference.com/mwiki/images/1/16/html_book_20190607.tar.xz
    URL_HASH SHA256=8f97b2baa749c748a2e022d785f1a2e95aa851a3075987dfcf38baf65e0e486d
    CONFIGURE_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_COMMAND ""
    EXCLUDE_FROM_ALL TRUE
)
ExternalProject_Get_Property(
    cppreference_tag_file
    SOURCE_DIR
)
list(
    APPEND tag_files_list
    "${SOURCE_DIR}/cppreference-doxygen-web.tag.xml=http://en.cppreference.com/w/"
)
list(APPEND tag_file_dependencies cppreference_tag_file)

list(JOIN tag_files_list " " DOXYGEN_TAGFILES)
