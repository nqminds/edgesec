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
include src/CMakeFiles/engine.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/engine.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/engine.dir/flags.make

src/CMakeFiles/engine.dir/engine.c.o: src/CMakeFiles/engine.dir/flags.make
src/CMakeFiles/engine.dir/engine.c.o: ../src/engine.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/CMakeFiles/engine.dir/engine.c.o"
	cd /home/alexandru/Projects/EDGESec/build/src && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/engine.dir/engine.c.o   -c /home/alexandru/Projects/EDGESec/src/engine.c

src/CMakeFiles/engine.dir/engine.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/engine.dir/engine.c.i"
	cd /home/alexandru/Projects/EDGESec/build/src && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/alexandru/Projects/EDGESec/src/engine.c > CMakeFiles/engine.dir/engine.c.i

src/CMakeFiles/engine.dir/engine.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/engine.dir/engine.c.s"
	cd /home/alexandru/Projects/EDGESec/build/src && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/alexandru/Projects/EDGESec/src/engine.c -o CMakeFiles/engine.dir/engine.c.s

# Object files for target engine
engine_OBJECTS = \
"CMakeFiles/engine.dir/engine.c.o"

# External object files for target engine
engine_EXTERNAL_OBJECTS =

src/libengine.a: src/CMakeFiles/engine.dir/engine.c.o
src/libengine.a: src/CMakeFiles/engine.dir/build.make
src/libengine.a: src/CMakeFiles/engine.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C static library libengine.a"
	cd /home/alexandru/Projects/EDGESec/build/src && $(CMAKE_COMMAND) -P CMakeFiles/engine.dir/cmake_clean_target.cmake
	cd /home/alexandru/Projects/EDGESec/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/engine.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/engine.dir/build: src/libengine.a

.PHONY : src/CMakeFiles/engine.dir/build

src/CMakeFiles/engine.dir/clean:
	cd /home/alexandru/Projects/EDGESec/build/src && $(CMAKE_COMMAND) -P CMakeFiles/engine.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/engine.dir/clean

src/CMakeFiles/engine.dir/depend:
	cd /home/alexandru/Projects/EDGESec/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/alexandru/Projects/EDGESec /home/alexandru/Projects/EDGESec/src /home/alexandru/Projects/EDGESec/build /home/alexandru/Projects/EDGESec/build/src /home/alexandru/Projects/EDGESec/build/src/CMakeFiles/engine.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/engine.dir/depend

