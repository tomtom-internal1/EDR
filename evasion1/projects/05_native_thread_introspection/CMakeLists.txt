cmake_minimum_required(VERSION 3.20)
project(05_native_thread_introspection C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_executable(05_native_thread_introspection main.c)
if(MSVC)
  target_compile_options(05_native_thread_introspection PRIVATE /W4 /WX /O2)
endif()

