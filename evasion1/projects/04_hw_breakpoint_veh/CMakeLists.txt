cmake_minimum_required(VERSION 3.20)
project(04_hw_breakpoint_veh C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_executable(04_hw_breakpoint_veh main.c)
if(MSVC)
 target_compile_options(04_hw_breakpoint_veh PRIVATE /W4 /WX /O2)
endif()

