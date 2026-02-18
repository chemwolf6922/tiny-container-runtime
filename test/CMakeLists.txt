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
    ../src/network/dns_forwarder.c
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

add_executable(test_nat_network_manager
    test_nat_network_manager.c
    ../src/network/nat_network_manager.c
    ../src/network/nat_network.c
    ../src/network/dns_forwarder.c
    ../src/network/nft_helper.c
    ../src/common/bitmap.c
)

target_include_directories(test_nat_network_manager PRIVATE
    ../src
    ../src/network
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBNL3_INCLUDE_DIRS}
    ${LIBNL_ROUTE3_INCLUDE_DIRS}
)

target_link_libraries(test_nat_network_manager
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

add_executable(test_container_manager
    test_container_manager.c
    ../src/container/container_manager.c
    ../src/container/crun_config.c
    ../src/image/image_manager.c
    ../src/network/dns_forwarder.c
    ../src/network/nat_network_manager.c
    ../src/network/nat_network.c
    ../src/network/nft_helper.c
    ../src/network/port_forwarder.c
    ../src/common/bitmap.c
    ../src/common/utils.c
)

target_include_directories(test_container_manager PRIVATE
    ../src
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBNL3_INCLUDE_DIRS}
    ${LIBNL_ROUTE3_INCLUDE_DIRS}
)

target_link_libraries(test_container_manager
    seccomp_resource
    cjson
    tev
    uuid
    ${LIBNL3_LIBRARIES}
    ${LIBNL_ROUTE3_LIBRARIES}
    nftables
)

add_executable(test_rpc
    test_rpc.c
    ../src/rpc/rpc_server.c
    ../src/rpc/rpc_client.c
)

target_include_directories(test_rpc PRIVATE
    ../src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(test_rpc tev cjson pthread)

# --------------------------------------------------------------------------
# test_tcr_client: helper binary (tcr client with test socket path)
# --------------------------------------------------------------------------
add_executable(test_tcr_client_helper
    ../src/tcr.c
    ../src/rpc/rpc_client.c
)

target_include_directories(test_tcr_client_helper PRIVATE
    ../src
)

target_compile_definitions(test_tcr_client_helper PRIVATE
    TCR_SOCKET_PATH="@tcr_client_test"
)

target_link_libraries(test_tcr_client_helper tev cjson)

# --------------------------------------------------------------------------
# test_tcr_client: the actual test runner
# --------------------------------------------------------------------------
add_executable(test_tcr_client
    test_tcr_client.c
    ../src/rpc/rpc_server.c
)

target_include_directories(test_tcr_client PRIVATE
    ../src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(test_tcr_client tev cjson pthread)

add_dependencies(test_tcr_client test_tcr_client_helper)

# --------------------------------------------------------------------------
# test_tcrd_helper: tcrd daemon with test socket path
# --------------------------------------------------------------------------
add_executable(test_tcrd_helper
    ../src/tcrd.c
    ../src/rpc/rpc_server.c
    ../src/container/container_manager.c
    ../src/container/crun_config.c
    ../src/image/image_manager.c
    ../src/network/dns_forwarder.c
    ../src/network/nat_network_manager.c
    ../src/network/nat_network.c
    ../src/network/nft_helper.c
    ../src/network/port_forwarder.c
    ../src/common/bitmap.c
    ../src/common/utils.c
)

target_include_directories(test_tcrd_helper PRIVATE
    ../src
    ${LIBNL3_INCLUDE_DIRS}
    ${LIBNL_ROUTE3_INCLUDE_DIRS}
)

target_compile_definitions(test_tcrd_helper PRIVATE
    TCR_SOCKET_PATH="@tcr_integration_test"
    TCR_LOCK_FILE="/tmp/tcrd_integration_test.lock"
)

target_link_libraries(test_tcrd_helper
    seccomp_resource
    cjson
    tev
    uuid
    ${LIBNL3_LIBRARIES}
    ${LIBNL_ROUTE3_LIBRARIES}
    nftables
)

# --------------------------------------------------------------------------
# test_tcr_helper: tcr client with test socket path (matching test_tcrd_helper)
# --------------------------------------------------------------------------
add_executable(test_tcr_helper
    ../src/tcr.c
    ../src/rpc/rpc_client.c
)

target_include_directories(test_tcr_helper PRIVATE
    ../src
)

target_compile_definitions(test_tcr_helper PRIVATE
    TCR_SOCKET_PATH="@tcr_integration_test"
)

target_link_libraries(test_tcr_helper tev cjson)
