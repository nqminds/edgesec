# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/alexandru/Projects/EDGESec

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/alexandru/Projects/EDGESec/build

# Include any dependencies generated for this target.
include tests/CMakeFiles/test_system_checks.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/test_system_checks.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/test_system_checks.dir/flags.make

tests/CMakeFiles/test_system_checks.dir/test_system_checks.c.o: tests/CMakeFiles/test_system_checks.dir/flags.make
tests/CMakeFiles/test_system_checks.dir/test_system_checks.c.o: ../tests/test_system_checks.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/CMakeFiles/test_system_checks.dir/test_system_checks.c.o"
	cd /home/alexandru/Projects/EDGESec/build/tests && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/test_system_checks.dir/test_system_checks.c.o   -c /home/alexandru/Projects/EDGESec/tests/test_system_checks.c

tests/CMakeFiles/test_system_checks.dir/test_system_checks.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_system_checks.dir/test_system_checks.c.i"
	cd /home/alexandru/Projects/EDGESec/build/tests && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/alexandru/Projects/EDGESec/tests/test_system_checks.c > CMakeFiles/test_system_checks.dir/test_system_checks.c.i

tests/CMakeFiles/test_system_checks.dir/test_system_checks.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_system_checks.dir/test_system_checks.c.s"
	cd /home/alexandru/Projects/EDGESec/build/tests && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/alexandru/Projects/EDGESec/tests/test_system_checks.c -o CMakeFiles/test_system_checks.dir/test_system_checks.c.s

# Object files for target test_system_checks
test_system_checks_OBJECTS = \
"CMakeFiles/test_system_checks.dir/test_system_checks.c.o"

# External object files for target test_system_checks
test_system_checks_EXTERNAL_OBJECTS =

tests/test_system_checks: tests/CMakeFiles/test_system_checks.dir/test_system_checks.c.o
tests/test_system_checks: tests/CMakeFiles/test_system_checks.dir/build.make
tests/test_system_checks: src/utils/liblog.a
tests/test_system_checks: src/libsystem_checks.a
tests/test_system_checks: src/utils/libos.a
tests/test_system_checks: src/utils/libhashmap.a
tests/test_system_checks: ../lib/cmocka-1.1.5/build/src/libcmocka.so
tests/test_system_checks: src/utils/libif.a
tests/test_system_checks: src/utils/libos.a
tests/test_system_checks: src/utils/libiw.a
tests/test_system_checks: src/utils/liblog.a
tests/test_system_checks: /lib/x86_64-linux-gnu/libnl-3.so
tests/test_system_checks: /lib/x86_64-linux-gnu/libnl-genl-3.so
tests/test_system_checks: ../lib/libnetlink/build/lib/liblibnetlink.so
tests/test_system_checks: ../lib/libnetlink/build/lib/libll_map.so
tests/test_system_checks: ../lib/libnetlink/build/lib/libutils.so
tests/test_system_checks: ../lib/libnetlink/build/lib/librt_names.so
tests/test_system_checks: ../lib/libnetlink/build/lib/libll_types.so
tests/test_system_checks: tests/CMakeFiles/test_system_checks.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable test_system_checks"
	cd /home/alexandru/Projects/EDGESec/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_system_checks.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/test_system_checks.dir/build: tests/test_system_checks

.PHONY : tests/CMakeFiles/test_system_checks.dir/build

tests/CMakeFiles/test_system_checks.dir/clean:
	cd /home/alexandru/Projects/EDGESec/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/test_system_checks.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/test_system_checks.dir/clean

tests/CMakeFiles/test_system_checks.dir/depend:
	cd /home/alexandru/Projects/EDGESec/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/alexandru/Projects/EDGESec /home/alexandru/Projects/EDGESec/tests /home/alexandru/Projects/EDGESec/build /home/alexandru/Projects/EDGESec/build/tests /home/alexandru/Projects/EDGESec/build/tests/CMakeFiles/test_system_checks.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/test_system_checks.dir/depend

