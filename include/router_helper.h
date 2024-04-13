#ifndef _ROUTER_HELPER_H_
#define _ROUTER_HELPER_H_

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "lib.h"
#include "struct_helper.h"

void temp_get_mac_from_arp_table(uint32_t ip, arp_table_entry *arp_table, int arp_table_size, uint8_t *mac);
void swap_ip_addresses(uint32_t *ip1, uint32_t *ip2);
void swap_mac_addresses(uint8_t *mac1, uint8_t *mac2);
int is_broadcast_mac(uint8_t *mac);
int verify_checksum(uint16_t *packet, ssize_t size, uint16_t* checksum_field);
void* prep_waiting_packet(char *buf, uint32_t next_hop_ip, int interface);
void send_echo_reply(char *received_icmp, int interface);
void send_error_packet(char *received_buff, int interface, int type, uint8_t *router_mac, uint32_t router_ip);
void send_arp_request(route_table_entry *entry);
void send_arp_reply(char *received_arp, int interface, uint8_t *int_mac);
void send_waiting_packets(queue *q_wait, arp_table *arp_table, uint32_t ipaddr, uint8_t *found_mac);

#endif