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
include src/supervisor/CMakeFiles/domain_server.dir/depend.make

# Include the progress variables for this target.
include src/supervisor/CMakeFiles/domain_server.dir/progress.make

# Include the compile flags for this target's objects.
include src/supervisor/CMakeFiles/domain_server.dir/flags.make

src/supervisor/CMakeFiles/domain_server.dir/domain_server.c.o: src/supervisor/CMakeFiles/domain_server.dir/flags.make
src/supervisor/CMakeFiles/domain_server.dir/domain_server.c.o: ../src/supervisor/domain_server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/supervisor/CMakeFiles/domain_server.dir/domain_server.c.o"
	cd /home/alexandru/Projects/EDGESec/build/src/supervisor && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/domain_server.dir/domain_server.c.o   -c /home/alexandru/Projects/EDGESec/src/supervisor/domain_server.c

src/supervisor/CMakeFiles/domain_server.dir/domain_server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/domain_server.dir/domain_server.c.i"
	cd /home/alexandru/Projects/EDGESec/build/src/supervisor && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/alexandru/Projects/EDGESec/src/supervisor/domain_server.c > CMakeFiles/domain_server.dir/domain_server.c.i

src/supervisor/CMakeFiles/domain_server.dir/domain_server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/domain_server.dir/domain_server.c.s"
	cd /home/alexandru/Projects/EDGESec/build/src/supervisor && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/alexandru/Projects/EDGESec/src/supervisor/domain_server.c -o CMakeFiles/domain_server.dir/domain_server.c.s

# Object files for target domain_server
domain_server_OBJECTS = \
"CMakeFiles/domain_server.dir/domain_server.c.o"

# External object files for target domain_server
domain_server_EXTERNAL_OBJECTS =

src/supervisor/libdomain_server.a: src/supervisor/CMakeFiles/domain_server.dir/domain_server.c.o
src/supervisor/libdomain_server.a: src/supervisor/CMakeFiles/domain_server.dir/build.make
src/supervisor/libdomain_server.a: src/supervisor/CMakeFiles/domain_server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C static library libdomain_server.a"
	cd /home/alexandru/Projects/EDGESec/build/src/supervisor && $(CMAKE_COMMAND) -P CMakeFiles/domain_server.dir/cmake_clean_target.cmake
	cd /home/alexandru/Projects/EDGESec/build/src/supervisor && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/domain_server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/supervisor/CMakeFiles/domain_server.dir/build: src/supervisor/libdomain_server.a

.PHONY : src/supervisor/CMakeFiles/domain_server.dir/build

src/supervisor/CMakeFiles/domain_server.dir/clean:
	cd /home/alexandru/Projects/EDGESec/build/src/supervisor && $(CMAKE_COMMAND) -P CMakeFiles/domain_server.dir/cmake_clean.cmake
.PHONY : src/supervisor/CMakeFiles/domain_server.dir/clean

src/supervisor/CMakeFiles/domain_server.dir/depend:
	cd /home/alexandru/Projects/EDGESec/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/alexandru/Projects/EDGESec /home/alexandru/Projects/EDGESec/src/supervisor /home/alexandru/Projects/EDGESec/build /home/alexandru/Projects/EDGESec/build/src/supervisor /home/alexandru/Projects/EDGESec/build/src/supervisor/CMakeFiles/domain_server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/supervisor/CMakeFiles/domain_server.dir/depend

