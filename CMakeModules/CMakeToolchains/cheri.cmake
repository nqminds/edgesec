set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -target aarch64-unknown-freebsd -march=morello+c64 -mabi=purecap -Xclang -morello-vararg=new")
