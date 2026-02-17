#pragma once

#include "nat_network.h"

#include <tev/tev.h>

#define NAT_NETWORK_MANAGER_DEFAULT_NAME "tcr_default"

typedef struct nat_network_manager_s* nat_network_manager;

/**
 * @brief Create a new NAT network manager.
 * 
 * @param tev The tev handle (passed to NAT networks for DNS forwarding).
 * @param root_path Path to store all NAT network state.
 * @return nat_network_manager 
 */
nat_network_manager nat_network_manager_new(tev_handle_t tev, const char* root_path);

/**
 * @brief Free a NAT network manager. This will remove all managed NAT networks.
 * 
 * @param manager The NAT network manager to free.
 */
void nat_network_manager_free(nat_network_manager manager);

/**
 * @brief Get a NAT network by name. Will create the network if it doesn't exist.
 * 
 * @param manager The NAT network manager to get the network from. 
 * @param name The name of the NAT network. If NULL, will use the default name.
 * @return nat_network. Owned by the manager and should not be freed by the caller. NULL if an error occurred.
 */
nat_network nat_network_manager_get_network(
    nat_network_manager manager,
    const char* name);

/**
 * @brief Remove a NAT network by name.
 * 
 * @param manager The NAT network manager to remove the network from.
 * @param name The name of the NAT network to remove. If NULL, will use the default name.
 */
void nat_network_remove_network(nat_network_manager manager, const char* name);

typedef void (*nat_network_manager_foreach_fn)(nat_network net, void* user_data);

/**
 * @brief Iterate over all NAT networks in the manager and call the given function for each network.
 * 
 * @param manager The NAT network manager to iterate over.
 * @param fn The function to call for each NAT network.
 * @param user_data User data to pass to the function.
 * @return int 0 on success, -1 if failed.
 */
int nat_network_manager_foreach_safe(nat_network_manager manager, nat_network_manager_foreach_fn fn, void* user_data);
