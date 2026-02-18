cmake_minimum_required(VERSION 3.10)
project(tcr C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Werror)

# ── tcr client ─────────────────────────────────────────────────────────────

add_executable(tcr
    src/tcr.c
    src/rpc/rpc_client.c
)

target_include_directories(tcr PRIVATE
    src
)

target_link_libraries(tcr tev cjson)

# ── tcrd daemon ────────────────────────────────────────────────────────────

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL3 REQUIRED libnl-3.0)
pkg_check_modules(LIBNL_ROUTE3 REQUIRED libnl-route-3.0)

add_subdirectory(src/resource)

add_executable(tcrd
    src/tcrd.c
    src/rpc/rpc_server.c
    src/container/container_manager.c
    src/container/crun_config.c
    src/image/image_manager.c
    src/network/dns_forwarder.c
    src/network/nat_network_manager.c
    src/network/nat_network.c
    src/network/nft_helper.c
    src/network/port_forwarder.c
    src/common/bitmap.c
    src/common/utils.c
)

target_include_directories(tcrd PRIVATE
    src
    ${LIBNL3_INCLUDE_DIRS}
    ${LIBNL_ROUTE3_INCLUDE_DIRS}
)

target_link_libraries(tcrd
    seccomp_resource
    cjson
    tev
    uuid
    ${LIBNL3_LIBRARIES}
    ${LIBNL_ROUTE3_LIBRARIES}
    nftables
)

# ── Install ────────────────────────────────────────────────────────────────

install(TARGETS tcr tcrd RUNTIME DESTINATION bin)

# Detect init system for install-service target
if(EXISTS /run/systemd/system)
    set(INIT_SYSTEM "systemd" CACHE STRING "Init system (systemd or busybox)")
else()
    set(INIT_SYSTEM "busybox" CACHE STRING "Init system (systemd or busybox)")
endif()

# install-service: install and enable the service file (separate from `make install`)
if(INIT_SYSTEM STREQUAL "systemd")
    add_custom_target(install-service
        COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/dist/systemd/tcrd.service /etc/systemd/system/tcrd.service
        COMMAND systemctl daemon-reload
        COMMAND systemctl enable tcrd
        COMMAND ${CMAKE_COMMAND} -E echo "Installed and enabled tcrd.service (systemd)"
        COMMENT "Install systemd service"
    )
elseif(INIT_SYSTEM STREQUAL "busybox")
    add_custom_target(install-service
        COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/dist/busybox-init/tcrd /etc/init.d/tcrd
        COMMAND chmod +x /etc/init.d/tcrd
        COMMAND ${CMAKE_COMMAND} -E echo "Installed /etc/init.d/tcrd (busybox init)"
        COMMENT "Install busybox init script"
    )
endif()

# ── Custom targets ─────────────────────────────────────────────────────────

# uninstall: remove installed files but keep data (/var/lib/tcr)
add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -E echo "Removing installed files..."
    COMMAND ${CMAKE_COMMAND} -E rm -f /usr/bin/tcr /usr/bin/tcrd /var/run/tcrd.lock
    COMMAND ${CMAKE_COMMAND} -E echo "Removing service files..."
    COMMAND ${CMAKE_COMMAND} -E rm -f /etc/systemd/system/tcrd.service /etc/init.d/tcrd
    COMMAND ${CMAKE_COMMAND} -E echo "Uninstall complete. Data in /var/lib/tcr preserved."
    COMMENT "Uninstall tcr/tcrd (data preserved)"
)

# nuke: remove everything including data and network artifacts
add_custom_target(nuke
    COMMAND ${CMAKE_SOURCE_DIR}/tools/tcr-nuke.sh
    COMMENT "Remove tcr/tcrd, all data, and network artifacts"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
