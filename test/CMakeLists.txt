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

add_executable(test_image_manager
    test_image_manager.c
    ../src/image/image_manager.c
    ../src/common/utils.c
)

target_include_directories(test_image_manager PRIVATE
    ../src
    ../src/image
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(test_image_manager tev cjson uuid)

add_subdirectory(../src/resource ${CMAKE_CURRENT_BINARY_DIR}/resource)

add_executable(test_seccomp_resource
    test_seccomp_resource.c
)

target_include_directories(test_seccomp_resource PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(test_seccomp_resource seccomp_resource cjson)

add_executable(test_crun_config
    test_crun_config.c
    ../src/container/crun_config.c
    ../src/image/image_manager.c
    ../src/common/utils.c
)

target_include_directories(test_crun_config PRIVATE
    ../src
    ../src/container
    ../src/image
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(test_crun_config seccomp_resource cjson tev uuid)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL3 REQUIRED libnl-3.0)
pkg_check_modules(LIBNL_ROUTE3 REQUIRED libnl-route-3.0)

add_executable(test_nat_network
    test_nat_network.c
    ../src/network/nat_network.c
    ../src/network/nft_helper.c
    ../src/common/bitmap.c
)

target_include_directories(test_nat_network PRIVATE
    ../src
    ../src/network
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBNL3_INCLUDE_DIRS}
    ${LIBNL_ROUTE3_INCLUDE_DIRS}
)

target_link_libraries(test_nat_network
    ${LIBNL3_LIBRARIES}
    ${LIBNL_ROUTE3_LIBRARIES}
    nftables
    tev
)

add_executable(test_port_forwarder
    test_port_forwarder.c
    ../src/network/port_forwarder.c
    ../src/network/nft_helper.c
)

target_include_directories(test_port_forwarder PRIVATE
    ../src
    ../src/network
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(test_port_forwarder nftables)
