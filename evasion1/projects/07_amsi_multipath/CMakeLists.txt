cmake_minimum_required(VERSION 3.20)
project(07_amsi_multipath C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(07_amsi_multipath main.c)
add_executable(07_amsi_multipath_sim simulator.c)

if(MSVC)
  target_compile_options(07_amsi_multipath PRIVATE /W4 /WX /O2)
  target_compile_options(07_amsi_multipath_sim PRIVATE /W4 /WX /O2)
endif()

target_link_libraries(07_amsi_multipath PRIVATE amsi bcrypt version)
