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
include src/hostapd/CMakeFiles/hostapd_service.dir/depend.make

# Include the progress variables for this target.
include src/hostapd/CMakeFiles/hostapd_service.dir/progress.make

# Include the compile flags for this target's objects.
include src/hostapd/CMakeFiles/hostapd_service.dir/flags.make

src/hostapd/CMakeFiles/hostapd_service.dir/hostapd_service.c.o: src/hostapd/CMakeFiles/hostapd_service.dir/flags.make
src/hostapd/CMakeFiles/hostapd_service.dir/hostapd_service.c.o: ../src/hostapd/hostapd_service.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/hostapd/CMakeFiles/hostapd_service.dir/hostapd_service.c.o"
	cd /home/alexandru/Projects/EDGESec/build/src/hostapd && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hostapd_service.dir/hostapd_service.c.o   -c /home/alexandru/Projects/EDGESec/src/hostapd/hostapd_service.c

src/hostapd/CMakeFiles/hostapd_service.dir/hostapd_service.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hostapd_service.dir/hostapd_service.c.i"
	cd /home/alexandru/Projects/EDGESec/build/src/hostapd && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/alexandru/Projects/EDGESec/src/hostapd/hostapd_service.c > CMakeFiles/hostapd_service.dir/hostapd_service.c.i

src/hostapd/CMakeFiles/hostapd_service.dir/hostapd_service.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hostapd_service.dir/hostapd_service.c.s"
	cd /home/alexandru/Projects/EDGESec/build/src/hostapd && /usr/bin/gcc-9 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/alexandru/Projects/EDGESec/src/hostapd/hostapd_service.c -o CMakeFiles/hostapd_service.dir/hostapd_service.c.s

# Object files for target hostapd_service
hostapd_service_OBJECTS = \
"CMakeFiles/hostapd_service.dir/hostapd_service.c.o"

# External object files for target hostapd_service
hostapd_service_EXTERNAL_OBJECTS =

src/hostapd/libhostapd_service.a: src/hostapd/CMakeFiles/hostapd_service.dir/hostapd_service.c.o
src/hostapd/libhostapd_service.a: src/hostapd/CMakeFiles/hostapd_service.dir/build.make
src/hostapd/libhostapd_service.a: src/hostapd/CMakeFiles/hostapd_service.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/alexandru/Projects/EDGESec/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C static library libhostapd_service.a"
	cd /home/alexandru/Projects/EDGESec/build/src/hostapd && $(CMAKE_COMMAND) -P CMakeFiles/hostapd_service.dir/cmake_clean_target.cmake
	cd /home/alexandru/Projects/EDGESec/build/src/hostapd && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/hostapd_service.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/hostapd/CMakeFiles/hostapd_service.dir/build: src/hostapd/libhostapd_service.a

.PHONY : src/hostapd/CMakeFiles/hostapd_service.dir/build

src/hostapd/CMakeFiles/hostapd_service.dir/clean:
	cd /home/alexandru/Projects/EDGESec/build/src/hostapd && $(CMAKE_COMMAND) -P CMakeFiles/hostapd_service.dir/cmake_clean.cmake
.PHONY : src/hostapd/CMakeFiles/hostapd_service.dir/clean

src/hostapd/CMakeFiles/hostapd_service.dir/depend:
	cd /home/alexandru/Projects/EDGESec/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/alexandru/Projects/EDGESec /home/alexandru/Projects/EDGESec/src/hostapd /home/alexandru/Projects/EDGESec/build /home/alexandru/Projects/EDGESec/build/src/hostapd /home/alexandru/Projects/EDGESec/build/src/hostapd/CMakeFiles/hostapd_service.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/hostapd/CMakeFiles/hostapd_service.dir/depend

