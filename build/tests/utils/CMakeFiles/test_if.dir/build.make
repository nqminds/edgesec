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
include tests/utils/CMakeFiles/test_if.dir/depend.make

# Include the progress variables for this target.
include tests/utils/CMakeFiles/test_if.dir/progress.make

# Include the compile flags for this target's objects.
include tests/utils/CMakeFiles/test_if.dir/flags.make

tests/utils/CMakeFiles/test_if.dir/test_if.c.o: tests/utils/CMakeFiles/test_if.dir/flags.make
tests/utils/CMakeFiles/test_if.dir/test_if.c.o: ../tests/utils/test_if.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/utils/CMakeFiles/test_if.dir/test_if.c.o"
	cd /home/alexandru/Projects/EDGESec/build/tests/utils && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/test_if.dir/test_if.c.o   -c /home/alexandru/Projects/EDGESec/tests/utils/test_if.c

tests/utils/CMakeFiles/test_if.dir/test_if.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_if.dir/test_if.c.i"
	cd /home/alexandru/Projects/EDGESec/build/tests/utils && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/alexandru/Projects/EDGESec/tests/utils/test_if.c > CMakeFiles/test_if.dir/test_if.c.i

tests/utils/CMakeFiles/test_if.dir/test_if.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_if.dir/test_if.c.s"
	cd /home/alexandru/Projects/EDGESec/build/tests/utils && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/alexandru/Projects/EDGESec/tests/utils/test_if.c -o CMakeFiles/test_if.dir/test_if.c.s

# Object files for target test_if
test_if_OBJECTS = \
"CMakeFiles/test_if.dir/test_if.c.o"

# External object files for target test_if
test_if_EXTERNAL_OBJECTS =

tests/utils/test_if: tests/utils/CMakeFiles/test_if.dir/test_if.c.o
tests/utils/test_if: tests/utils/CMakeFiles/test_if.dir/build.make
tests/utils/test_if: src/utils/libif.a
tests/utils/test_if: ../lib/cmocka-1.1.5/build/src/libcmocka.so
tests/utils/test_if: /lib/x86_64-linux-gnu/libnl-3.so
tests/utils/test_if: /lib/x86_64-linux-gnu/libnl-genl-3.so
tests/utils/test_if: ../lib/libnetlink/build/lib/liblibnetlink.so
tests/utils/test_if: ../lib/libnetlink/build/lib/libll_map.so
tests/utils/test_if: ../lib/libnetlink/build/lib/libutils.so
tests/utils/test_if: ../lib/libnetlink/build/lib/librt_names.so
tests/utils/test_if: ../lib/libnetlink/build/lib/libll_types.so
tests/utils/test_if: src/utils/libos.a
tests/utils/test_if: src/utils/liblog.a
tests/utils/test_if: tests/utils/CMakeFiles/test_if.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable test_if"
	cd /home/alexandru/Projects/EDGESec/build/tests/utils && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_if.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/utils/CMakeFiles/test_if.dir/build: tests/utils/test_if

.PHONY : tests/utils/CMakeFiles/test_if.dir/build

tests/utils/CMakeFiles/test_if.dir/clean:
	cd /home/alexandru/Projects/EDGESec/build/tests/utils && $(CMAKE_COMMAND) -P CMakeFiles/test_if.dir/cmake_clean.cmake
.PHONY : tests/utils/CMakeFiles/test_if.dir/clean

tests/utils/CMakeFiles/test_if.dir/depend:
	cd /home/alexandru/Projects/EDGESec/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/alexandru/Projects/EDGESec /home/alexandru/Projects/EDGESec/tests/utils /home/alexandru/Projects/EDGESec/build /home/alexandru/Projects/EDGESec/build/tests/utils /home/alexandru/Projects/EDGESec/build/tests/utils/CMakeFiles/test_if.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/utils/CMakeFiles/test_if.dir/depend

