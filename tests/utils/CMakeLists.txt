include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(tmpdir OBJECT tmpdir.c)
target_link_libraries(tmpdir PRIVATE log cmocka::cmocka)

if (USE_UCI_SERVICE)
  add_compile_definitions(UCI_CONFIG_DIR="${UCI_CONFIG_DIR}")
  add_library(__wrap_uwrt_init_context OBJECT __wrap_uwrt_init_context.c)
  target_link_libraries(__wrap_uwrt_init_context PRIVATE uci_wrt)
  target_link_options(__wrap_uwrt_init_context PUBLIC "-Wl,--wrap=uwrt_init_context")
  add_cmocka_test(test_uci_wrt
    SOURCES test_uci_wrt.c
    LINK_LIBRARIES uci_wrt cmocka::cmocka iface_mapper)
endif ()

add_cmocka_test(test_iface_mapper
  SOURCES test_iface_mapper.c
  LINK_LIBRARIES iface_mapper cmocka::cmocka)

add_cmocka_test(test_ifaceu
  SOURCES test_ifaceu.c
  LINK_LIBRARIES ifaceu cmocka::cmocka)

add_cmocka_test(test_net
  SOURCES test_net.c
  LINK_LIBRARIES net cmocka::cmocka)

add_cmocka_test(test_os
  SOURCES test_os.c
  LINK_LIBRARIES tmpdir os allocs hashmap cmocka::cmocka)

add_cmocka_test(test_eloop
  SOURCES test_eloop.c
  LINK_LIBRARIES tmpdir sockctl allocs eloop::eloop cmocka::cmocka)
# requires the POSIX.1-2008 to define PATH_MAX
# (POSIX.1-2001 has some issues, see https://man7.org/linux/man-pages/man3/realpath.3.html)
target_compile_definitions(test_eloop PRIVATE _POSIX_C_SOURCE=200809L)

add_cmocka_test(test_eloop_handles_null
  SOURCES test_eloop_handles_null.c
  LINK_LIBRARIES
  PRIVATE eloop::eloop cmocka::cmocka wrap_log_error
)

add_cmocka_test(test_eloop_threaded
  SOURCES test_eloop_threaded.c
  LINK_LIBRARIES eloop::eloop cmocka::cmocka sockctl LibUTHash::LibUTHash Threads::Threads
)
set_tests_properties(test_eloop_threaded
  PROPERTIES
  WILL_FAIL FALSE
  ENVIRONMENT CMOCKA_TEST_ABORT='1' # these tests uses threading
)

add_cmocka_test(test_sqliteu
  SOURCES test_sqliteu.c
  LINK_LIBRARIES sqliteu cmocka::cmocka)

add_cmocka_test(test_hashmap
  SOURCES test_hashmap.c
  LINK_LIBRARIES hashmap cmocka::cmocka)

add_cmocka_test(test_utarray
  SOURCES test_utarray.c
  LINK_LIBRARIES LibUTHash::LibUTHash cmocka::cmocka)

add_cmocka_test(test_minIni
  SOURCES test_minIni.c
  LINK_LIBRARIES MinIni::minIni cmocka::cmocka)

add_cmocka_test(test_squeue
  SOURCES test_squeue.c
  LINK_LIBRARIES squeue os cmocka::cmocka)

add_cmocka_test(test_log_thread_safe
  SOURCES test_log_thread_safe.c
  LINK_LIBRARIES log Threads::Threads)

add_cmocka_test(test_log_level
  SOURCES test_log_level.c
  LINK_LIBRARIES log)
set_tests_properties(test_log_level
  PROPERTIES PASS_REGULAR_EXPRESSION ".+TRACE.+Hello world;.+DEBUG.+Hello world;.+INFO.+Hello world;.+WARN.+Hello world")

add_cmocka_test(test_log_err
  SOURCES test_log_err.c
  LINK_LIBRARIES log)
set_tests_properties(test_log_err
  PROPERTIES
  PASS_REGULAR_EXPRESSION ".+ERROR")

add_library(wrap_log_error OBJECT wrap_log_error.c)
target_link_libraries(wrap_log_error PRIVATE log cmocka::cmocka)
target_link_options(wrap_log_error PUBLIC "LINKER:--wrap=log_levels")

add_cmocka_test(test_wrap_log_error
  SOURCES test_wrap_log_error.c
  LINK_LIBRARIES log cmocka::cmocka wrap_log_error)

if (USE_NETLINK_SERVICE)
  add_cmocka_test(test_nl
    SOURCES test_nl.c
    LINK_LIBRARIES cmocka::cmocka nl wrap_log_error
  )
endif()
