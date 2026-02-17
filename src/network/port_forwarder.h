#pragma once

#include <netinet/in.h>

#define PORT_FORWARDER_PROTOCOL_TCP (1<<0)
#define PORT_FORWARDER_PROTOCOL_UDP (1<<1)

typedef struct port_forwarder_s* port_forwarder;

/**
 * @brief Forward port target_ip:target_port to listen_ip:listen_port for the specified protocols.
 * After forwarding, access listen_ip:listen_port will be forwarded to target_ip:target_port.
 * 
 * @param table_name The nftables table to add the forwarding rules. 
 * @param group_id Used for labeling the forwarding rules for batch cleanup. The actual label will be "tcr-$group_id".
 * @param listen_ip
 * @param listen_port 
 * @param target_ip 
 * @param target_port 
 * @param protocols Bitmask of PORT_FORWARDER_PROTOCOL_TCP and/or PORT_FORWARDER_PROTOCOL_UDP. 
 * @return port_forwarder, or NULL if an error occurred.
 */
port_forwarder port_forwarder_new(
    const char* table_name,
    const char* group_id,
    struct in_addr listen_ip, uint16_t listen_port,
    struct in_addr target_ip, uint16_t target_port,
    int protocols);

/**
 * @brief Cleanup the port forwarder and remove forwarding rules associated with it.
 * 
 * @param forwarder The port forwarder to be cleaned up.
 */
void port_forwarder_free(port_forwarder forwarder);

/**
 * @brief Cleanup all forwarding rules labeled with the specified group_id.
 * @warning This is only for cleanup purposes. DO NOT call this during normal operation
 * as it will invalidate all active port_forwarder objects with the same group_id.
 * 
 * @param table_name The nftables table to clean up the forwarding rules from.
 * @param group_id The group ID whose forwarding rules should be cleaned up.
 */
void port_forwarder_cleanup_group(const char* table_name, const char* group_id);
