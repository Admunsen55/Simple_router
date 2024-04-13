#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "struct_helper.h"
#include "queue.h"
#include "constants.h"
#include "string.h"

#include "router_helper.h"

arp_table* create_arp_table() {
    arp_table *t = malloc(sizeof(arp_table));

    t->entries = malloc(sizeof(arp_table_entry) * MAX_ARP_TABLE_SIZE);
    t->size = 0;
    return t;
}

void add_arp_table_entry(arp_table *t, uint32_t ip, uint8_t *mac) {
    if (t->size >= MAX_ARP_TABLE_SIZE) {
        // eliminam primul element (cel mai vechi)
        for (int i = 0; i < MAX_ARP_TABLE_SIZE - 1; i++) {
            memcpy(&(t->entries[i]), &(t->entries[i + 1]), sizeof(arp_table_entry));
        }
    }
    t->entries[t->size].ip = ip;
    memcpy(t->entries[t->size].mac, mac, 6);
    t->size++;
}


int get_arp_table_entry(arp_table *t, uint32_t ip, uint8_t *mac) {
    for (int i = 0; i < t->size; i++) {
        if (t->entries[i].ip == ip) {
            memcpy(mac, t->entries[i].mac, 6);
            return 1;
        }
    }
    // nu exista intrare pentru aceasta adresa IP
    return 0;
}

trie_node* create_trie_node() {
    trie_node *node = malloc(sizeof(trie_node));
    node->entry = NULL;
    node->children_bits[0] = NULL;
    node->children_bits[1] = NULL;
    return node;
}

int get_mask_size(uint32_t mask) {
    int mask_size = 0;
    while (mask != 0) {
        mask_size++;
        mask <<= 1;
    }
    return mask_size;
}

void add_route_to_trie(trie_node *root, route_table_entry *entry) {
    trie_node *current = root;
    uint32_t mask = ntohl(entry->mask);
    uint32_t prefix = ntohl(entry->prefix);
    uint8_t byte;
    int poz = 31;
    int mask_size = get_mask_size(mask);
    // parcurgem bitii din masca
    for (int i = 0; i < mask_size; i++) {
        // extragem bitul de pe pozitia poz + 1 din prefix (de la dreapta la stanga)
        byte = (prefix >> poz) & 1;
        if (byte != 0 && byte != 1) {
            printf("ESTI PROST\n");
            break;
        }
        // daca nodul nu exista, il cream
        if (current->children_bits[byte] == NULL) {
            current->children_bits[byte] = create_trie_node();
        }
        current = current->children_bits[byte];
        // trecem la urmatorul bit
        poz--;
    }
    
    current->entry = entry;
}

route_table_entry* get_best_route_from_trie(trie_node *root, uint32_t dest_ip) {
    trie_node *current = root;
    uint32_t host_order_ip = ntohl(dest_ip);
    route_table_entry *best_route = NULL;
    int poz = 31;
    // parcurgem bitii din adresa IP (pentru a ne asigura ca gasim potrivirea cea mai lunga)
    while (current != NULL && poz >= 0) {
        // daca am gasit o ruta, o salvam
        if (current->entry != NULL) {
            best_route = current->entry;
        }
        int bit = (host_order_ip >> poz) & 1;
        current = current->children_bits[bit];
        poz--;
    }
    return best_route;
}

void free_trie(trie_node *root) {
    if (root == NULL) {
        return;
    }
    free_trie(root->children_bits[0]);
    free_trie(root->children_bits[1]);
    free(root);
}