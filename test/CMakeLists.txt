cmake_minimum_required(VERSION 3.10)
project(tcr_tests C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra -Werror)

add_executable(test_dns_forwarder
    test_dns_forwarder.c
    ../src/network/dns_forwarder.c
)

target_include_directories(test_dns_forwarder PRIVATE
    ../src/network
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(test_dns_forwarder tev)
