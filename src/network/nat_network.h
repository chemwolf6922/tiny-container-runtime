#pragma once

#include <netinet/in.h>

typedef struct nat_network_s* nat_network;

/**
 * @brief [Re]create a NAT network.
 * @note Only one nat_network object can exist system wide for a given name.
 * 
 * @param name The name of the NAT network.
 * @param subnet The subnet of the NAT network. For example: 10.0.0.0/24
 * @param lockfile_root The root directory for the lockfile.
 * @return nat_network , or NULL if an error occurred.
 */
nat_network nat_network_new(const char* name, const char* subnet, const char* lockfile_root);

/**
 * @brief Free the nat_network object. Release all resources associated with the NAT network.
 * 
 * @param network The NAT network to free.
 */
void nat_network_free(nat_network network);

/**
 * @brief Get the gateway IP address of the NAT network.
 * 
 * @param network The NAT network to query.
 * @param out The output parameter to store the gateway IP address.
 * @return int 0 on success, or -1 if an error occurred.
 */
int nat_network_get_gateway(nat_network network, struct in_addr* out);

/**
 * @brief Allocate an IP address from the NAT network's subnet. 
 * 
 * @param network The NAT network to allocate an IP address from.
 * @param out The output parameter to store the allocated IP address.
 * @return int 0 on success, or -1 if an error occurred.
 */
int nat_network_allocate_ip(nat_network network, struct in_addr* out);

/**
 * @brief Reserve a specific IP address in the NAT network's subnet.
 * 
 * @param network The NAT network to reserve the IP address in.
 * @param ip The IP address to reserve.
 * @return int 0 on success, or -1 if an error occurred.
 */
int nat_network_reserve_ip(nat_network network, struct in_addr ip);

/**
 * @brief Release a previously allocated or reserved IP address back to the NAT network's pool of available addresses.
 * 
 * @param network The NAT network to release the IP address from.
 * @param ip The IP address to release.
 * @return int 0 on success, or -1 if an error occurred.
 */
int nat_network_release_ip(nat_network network, struct in_addr ip);

/**
 * @brief Create a network namespace that's connected to the NAT network and ready to use in a container.
 * 
 * @param network The NAT network to connect the namespace to.
 * @param namespace_name The name of the network namespace to [re]create.
 * @param ip The IP address to assign to the namespace.
 * @return int 0 on success, or -1 if an error occurred.
 */
int nat_network_create_network_namespace(
    nat_network network, const char* namespace_name, struct in_addr ip);

/**
 * @brief Remove the specified network namespace.
 * 
 * @param network The NAT network to disconnect the namespace from.
 * @param namespace_name The name of the network namespace to remove.
 * @return int 0 on success, or -1 if an error occurred.
 */
int nat_network_remove_network_namespace(nat_network network, const char* namespace_name);
