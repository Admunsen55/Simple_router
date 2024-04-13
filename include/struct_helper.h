#ifndef _STRUCT_HELPER_H_
#define _STRUCT_HELPER_H_

#include <unistd.h>
#include <stdint.h>

#include "constants.h"
#include "lib.h"

typedef struct waiting_packet {
    char buffer[ICMP_LEN];
    int packet_len;
    uint32_t next_hop_ip;
    int interface;
} waiting_packet;

typedef struct arp_table {
    arp_table_entry *entries;
    int size;
} arp_table;

typedef struct trie_node {
    struct trie_node *children_bits[2];
    route_table_entry *entry;
} trie_node;

arp_table* create_arp_table();
void add_arp_table_entry(arp_table *t, uint32_t ip, uint8_t *mac);
int get_arp_table_entry(arp_table *t, uint32_t ip, uint8_t *mac);

trie_node* create_trie_node();
void add_route_to_trie(trie_node *root, route_table_entry *entry);
route_table_entry* get_best_route_from_trie(trie_node *root, uint32_t dest_ip);
void free_trie(trie_node *root);

#endif