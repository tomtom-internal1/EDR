cmake_minimum_required(VERSION 3.20)
project(08_sec_image_mapping C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_executable(08_sec_image_mapping main.c)
if(MSVC)
  target_compile_options(08_sec_image_mapping PRIVATE /W4 /WX /O2)
endif()

