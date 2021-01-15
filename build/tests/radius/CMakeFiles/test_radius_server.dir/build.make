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
include tests/radius/CMakeFiles/test_radius_server.dir/depend.make

# Include the progress variables for this target.
include tests/radius/CMakeFiles/test_radius_server.dir/progress.make

# Include the compile flags for this target's objects.
include tests/radius/CMakeFiles/test_radius_server.dir/flags.make

tests/radius/CMakeFiles/test_radius_server.dir/test_radius_server.c.o: tests/radius/CMakeFiles/test_radius_server.dir/flags.make
tests/radius/CMakeFiles/test_radius_server.dir/test_radius_server.c.o: ../tests/radius/test_radius_server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/radius/CMakeFiles/test_radius_server.dir/test_radius_server.c.o"
	cd /home/alexandru/Projects/EDGESec/build/tests/radius && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/test_radius_server.dir/test_radius_server.c.o   -c /home/alexandru/Projects/EDGESec/tests/radius/test_radius_server.c

tests/radius/CMakeFiles/test_radius_server.dir/test_radius_server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_radius_server.dir/test_radius_server.c.i"
	cd /home/alexandru/Projects/EDGESec/build/tests/radius && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/alexandru/Projects/EDGESec/tests/radius/test_radius_server.c > CMakeFiles/test_radius_server.dir/test_radius_server.c.i

tests/radius/CMakeFiles/test_radius_server.dir/test_radius_server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_radius_server.dir/test_radius_server.c.s"
	cd /home/alexandru/Projects/EDGESec/build/tests/radius && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/alexandru/Projects/EDGESec/tests/radius/test_radius_server.c -o CMakeFiles/test_radius_server.dir/test_radius_server.c.s

# Object files for target test_radius_server
test_radius_server_OBJECTS = \
"CMakeFiles/test_radius_server.dir/test_radius_server.c.o"

# External object files for target test_radius_server
test_radius_server_EXTERNAL_OBJECTS =

tests/radius/test_radius_server: tests/radius/CMakeFiles/test_radius_server.dir/test_radius_server.c.o
tests/radius/test_radius_server: tests/radius/CMakeFiles/test_radius_server.dir/build.make
tests/radius/test_radius_server: tests/radius/libradius_client.a
tests/radius/test_radius_server: tests/radius/libip_addr.a
tests/radius/test_radius_server: src/radius/libradius.a
tests/radius/test_radius_server: src/radius/libradius_server.a
tests/radius/test_radius_server: src/radius/libmd5.a
tests/radius/test_radius_server: src/radius/libwpabuf.a
tests/radius/test_radius_server: src/utils/liblog.a
tests/radius/test_radius_server: src/utils/libos.a
tests/radius/test_radius_server: src/utils/libeloop.a
tests/radius/test_radius_server: ../lib/cmocka-1.1.5/build/src/libcmocka.so
tests/radius/test_radius_server: src/radius/libradius.a
tests/radius/test_radius_server: src/radius/libmd5.a
tests/radius/test_radius_server: src/radius/libmd5_internal.a
tests/radius/test_radius_server: src/radius/libwpabuf.a
tests/radius/test_radius_server: src/utils/libos.a
tests/radius/test_radius_server: src/utils/liblog.a
tests/radius/test_radius_server: tests/radius/CMakeFiles/test_radius_server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable test_radius_server"
	cd /home/alexandru/Projects/EDGESec/build/tests/radius && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_radius_server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/radius/CMakeFiles/test_radius_server.dir/build: tests/radius/test_radius_server

.PHONY : tests/radius/CMakeFiles/test_radius_server.dir/build

tests/radius/CMakeFiles/test_radius_server.dir/clean:
	cd /home/alexandru/Projects/EDGESec/build/tests/radius && $(CMAKE_COMMAND) -P CMakeFiles/test_radius_server.dir/cmake_clean.cmake
.PHONY : tests/radius/CMakeFiles/test_radius_server.dir/clean

tests/radius/CMakeFiles/test_radius_server.dir/depend:
	cd /home/alexandru/Projects/EDGESec/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/alexandru/Projects/EDGESec /home/alexandru/Projects/EDGESec/tests/radius /home/alexandru/Projects/EDGESec/build /home/alexandru/Projects/EDGESec/build/tests/radius /home/alexandru/Projects/EDGESec/build/tests/radius/CMakeFiles/test_radius_server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/radius/CMakeFiles/test_radius_server.dir/depend

