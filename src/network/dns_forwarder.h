#pragma once

#include <stdint.h>
#include <tev/tev.h>


/**
 * @brief Event loop backed DNS forwarder.
 * This component forwards DNS queries from the specified address:port to the host.
 * While allowing DNS overrides to be added and removed at runtime.
 */

typedef struct dns_forwarder_s* dns_forwarder;

/**
 * @brief Create a new DNS forwarder.
 * 
 * @param tev The tev handle.
 * @param listen_addr The address to listen on.
 * @param listen_port The port to listen on.
 * @return dns_forwarder The created DNS forwarder. NULL on failure.
 */
dns_forwarder dns_forwarder_new(tev_handle_t tev, const char* listen_addr, uint16_t listen_port);

/**
 * @brief Free a DNS forwarder.
 * 
 * @param forwarder The DNS forwarder to free.
 */
void dns_forwarder_free(dns_forwarder forwarder);

/**
 * @brief Add a DNS lookup entry.
 * 
 * @param forwarder The DNS forwarder.
 * @param domain The domain name.
 * @param ip The IP address.
 * @return int 0 on success, -1 on failure.
 */
int dns_forwarder_add_lookup(dns_forwarder forwarder, const char* domain, const char* ip);

/**
 * @brief Remove a DNS lookup entry.
 * 
 * @param forwarder The DNS forwarder.
 * @param domain The domain name.
 * @return int 0 on success, -1 on failure.
 */
int dns_forwarder_remove_lookup(dns_forwarder forwarder, const char* domain);
