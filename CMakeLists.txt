cmake_minimum_required(VERSION 3.10)
project(tcr C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Werror)

add_executable(tcr
    src/tcr.c
    src/rpc/rpc_client.c
)

target_include_directories(tcr PRIVATE
    src
)

target_link_libraries(tcr tev cjson)
