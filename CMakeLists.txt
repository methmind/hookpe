cmake_minimum_required(VERSION 4.1)
project(hookpe)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(external/radiance)

add_executable(hookpe main.cpp)

target_compile_options(hookpe PRIVATE -mcx16)

target_link_libraries(hookpe PRIVATE ntdll ktmw32 radiance)