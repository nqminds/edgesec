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
include tests/supervisor/CMakeFiles/test_cmd_processor.dir/depend.make

# Include the progress variables for this target.
include tests/supervisor/CMakeFiles/test_cmd_processor.dir/progress.make

# Include the compile flags for this target's objects.
include tests/supervisor/CMakeFiles/test_cmd_processor.dir/flags.make

tests/supervisor/CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.o: tests/supervisor/CMakeFiles/test_cmd_processor.dir/flags.make
tests/supervisor/CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.o: ../tests/supervisor/test_cmd_processor.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/supervisor/CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.o"
	cd /home/alexandru/Projects/EDGESec/build/tests/supervisor && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.o   -c /home/alexandru/Projects/EDGESec/tests/supervisor/test_cmd_processor.c

tests/supervisor/CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.i"
	cd /home/alexandru/Projects/EDGESec/build/tests/supervisor && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/alexandru/Projects/EDGESec/tests/supervisor/test_cmd_processor.c > CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.i

tests/supervisor/CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.s"
	cd /home/alexandru/Projects/EDGESec/build/tests/supervisor && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/alexandru/Projects/EDGESec/tests/supervisor/test_cmd_processor.c -o CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.s

# Object files for target test_cmd_processor
test_cmd_processor_OBJECTS = \
"CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.o"

# External object files for target test_cmd_processor
test_cmd_processor_EXTERNAL_OBJECTS =

tests/supervisor/test_cmd_processor: tests/supervisor/CMakeFiles/test_cmd_processor.dir/test_cmd_processor.c.o
tests/supervisor/test_cmd_processor: tests/supervisor/CMakeFiles/test_cmd_processor.dir/build.make
tests/supervisor/test_cmd_processor: src/supervisor/libcmd_processor.a
tests/supervisor/test_cmd_processor: src/utils/liblog.a
tests/supervisor/test_cmd_processor: ../lib/cmocka-1.1.5/build/src/libcmocka.so
tests/supervisor/test_cmd_processor: src/utils/libos.a
tests/supervisor/test_cmd_processor: src/utils/liblog.a
tests/supervisor/test_cmd_processor: tests/supervisor/CMakeFiles/test_cmd_processor.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable test_cmd_processor"
	cd /home/alexandru/Projects/EDGESec/build/tests/supervisor && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_cmd_processor.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/supervisor/CMakeFiles/test_cmd_processor.dir/build: tests/supervisor/test_cmd_processor

.PHONY : tests/supervisor/CMakeFiles/test_cmd_processor.dir/build

tests/supervisor/CMakeFiles/test_cmd_processor.dir/clean:
	cd /home/alexandru/Projects/EDGESec/build/tests/supervisor && $(CMAKE_COMMAND) -P CMakeFiles/test_cmd_processor.dir/cmake_clean.cmake
.PHONY : tests/supervisor/CMakeFiles/test_cmd_processor.dir/clean

tests/supervisor/CMakeFiles/test_cmd_processor.dir/depend:
	cd /home/alexandru/Projects/EDGESec/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/alexandru/Projects/EDGESec /home/alexandru/Projects/EDGESec/tests/supervisor /home/alexandru/Projects/EDGESec/build /home/alexandru/Projects/EDGESec/build/tests/supervisor /home/alexandru/Projects/EDGESec/build/tests/supervisor/CMakeFiles/test_cmd_processor.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/supervisor/CMakeFiles/test_cmd_processor.dir/depend

