#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include <arpa/inet.h>

#include "constants.h"
#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "struct_helper.h"

void temp_get_mac_from_arp_table(uint32_t ip, arp_table_entry *arp_table, int arp_table_size, uint8_t *mac) {
    for (int i = 0; i < arp_table_size; i++) {
        if (arp_table[i].ip == ip) {
            memcpy(mac, arp_table[i].mac, 6);
            return;
        }
    }
}

void swap_ip_addresses(uint32_t *ip1, uint32_t *ip2) {
    uint32_t aux = *ip1;
    *ip1 = *ip2;
    *ip2 = aux;
}

void swap_mac_addresses(uint8_t *mac1, uint8_t *mac2) {
    uint8_t aux[6];
    memcpy(aux, mac1, MAC_SIZE);
    memcpy(mac1, mac2, MAC_SIZE);
    memcpy(mac2, aux, MAC_SIZE);
}

// Functie care verifica daca adresa MAC este de tip broadcast
int is_broadcast_mac(uint8_t *mac) {
    for (int i = 0; i < MAC_SIZE; i++) {
        if (mac[i] != BROADCAST_MAC_OCTET) {
            return 0;
        }
    }
    return 1;
}

// Functie care seteaza checksum-ul la 0 si il verifica
int verify_checksum(uint16_t *packet, ssize_t size, uint16_t* checksum_field) {
    uint16_t expected_checksum = ntohs(*checksum_field);
    *checksum_field = 0;

    if (checksum(packet, size) == expected_checksum) {
        return 1;
    }
    return 0;
}

// Functie care pregateste un pachet pentru a fi trimis mai tarziu
// In cazul nostru pachetul este de tip ICMP
void* prep_waiting_packet(char *buf, uint32_t next_hop_ip, int interface) {
    waiting_packet *packet = (waiting_packet*)malloc(sizeof(waiting_packet));
    DIE(packet == NULL, "malloc");

    memcpy(packet->buffer, buf, ICMP_LEN);
    packet->packet_len = ICMP_LEN;
    packet->next_hop_ip = next_hop_ip;
    packet->interface = interface;

    return (void*)packet;
}

void init_ip_packet_header(ip_header *ip_hdr) {
    ip_hdr->tos = 0;
    ip_hdr->frag_off = 0;
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->id = 1;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->ttl = TTL_FULL;
}

void prep_ip_header_for_net(ip_header *ip_hdr, uint16_t tot_len, uint32_t saddr, uint32_t daddr) {
    init_ip_packet_header(ip_hdr);
    ip_hdr->tot_len = htons(tot_len);
    ip_hdr->id = htons(ip_hdr->id);
    ip_hdr->saddr = saddr;
    ip_hdr->daddr = daddr;
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(ip_header)));  
}

void init_arp_header(arp_header *arp_hdr) {
    arp_hdr->htype = htons(MAC_FORMAT_CODE);
    arp_hdr->ptype = htons(ETHERTYPE_IP);
    arp_hdr->hlen = MAC_SIZE;
    arp_hdr->plen = IPV4_SIZE;
}

// Functie care trimite un pachet de tip ICMP Echo Reply
void send_echo_reply(char *received_icmp, int interface) {
	// Extract the Ethernet, IP and ICMP headers
	eth_header *eth_hdr = (eth_header*)received_icmp;
    ip_header *ip_hdr = (ip_header*)(received_icmp + sizeof(eth_header));
    icmp_header *icmp_hdr = (icmp_header*)(received_icmp + sizeof(ip_header) + sizeof(ip_header));
	
    // creeam un pachet de tip ICMP Echo Reply
	icmp_hdr->type = TYPE_ECHO_REPLY_VAL;
	icmp_hdr->code = CODE_ICMP;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(ip_header)));

	// actualizam datele antetului IP
	swap_ip_addresses(&ip_hdr->saddr, &ip_hdr->daddr);
	ip_hdr->ttl--;
    ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(ip_header)));

    // actualizam datele antetului Ethernet
    swap_mac_addresses(eth_hdr->ether_shost, eth_hdr->ether_dhost);
    eth_hdr->ether_type = htons(ETHERTYPE_IP);

	send_to_link(interface, received_icmp, ICMP_LEN);
}

// Functie care trimite un pachet de tip ICMP Error (Destination Unreachable sau Time Exceeded)
void send_error_packet(char *received_buff, int interface, int type, uint8_t *router_mac, uint32_t router_ip) {
    size_t total_len = sizeof(eth_header) + sizeof(ip_header) + sizeof(icmp_header) + FORMER_PAYLOAD_SIZE_CPY;
    eth_header *eth_hdr = (eth_header *)received_buff;
    ip_header *ip_hdr = (ip_header *)(received_buff + sizeof(eth_header));
    icmp_header *icmp_hdr = (icmp_header *)(received_buff + sizeof(eth_header) + sizeof(ip_header));
    char *payload_p = (char*)icmp_hdr + sizeof(icmp_header);  
    int icmp_len = sizeof(icmp_header) + FORMER_PAYLOAD_SIZE_CPY; //dim icmp_header + payload
    int ip_len = sizeof(ip_header) + icmp_len; //dim ip_header + icmp_header + payload

    // Copiam primii 64 de biti (8 octeti) din payload-ul initial
    memcpy(payload_p, ip_hdr, FORMER_PAYLOAD_SIZE_CPY);
    
    // Setam datele antetului ICMP
    memset((void*)icmp_hdr, 0,  sizeof(icmp_header));
    icmp_hdr->type = type;
    icmp_hdr->code = CODE_ICMP;
    // Calculam checksum-ul antetului ICMP
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, icmp_len));

    // Setam datele antetului IP
    prep_ip_header_for_net(ip_hdr, ip_len, router_ip, ip_hdr->saddr);

    // Setam datele antetului Ethernet
    eth_hdr->ether_type = htons(ETHERTYPE_IP);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    memcpy(eth_hdr->ether_shost, router_mac, 6);

    // Trimitem pachetul
    send_to_link(interface, received_buff, total_len);
}

// Functie care trimite un pachet de tip ARP Request
void send_arp_request(route_table_entry *entry) {
    // memoram datele pachetului ARP Request local sa nu interferam cu datele pachetului
    // pentru care trimitem ARP Request
    char arp_packet[ARP_LEN];
    eth_header *eth_hdr = (eth_header *)arp_packet;
    arp_header *arp_hdr = (arp_header *)(arp_packet + sizeof(eth_header));

    // Actualizam datele antetului Ethernet
	eth_hdr->ether_type = htons(ETHERTYPE_ARP); 
	get_interface_mac(entry->interface, eth_hdr->ether_shost);
	for (int i = 0; i < MAC_SIZE; i++) {
        eth_hdr->ether_dhost[i] = BROADCAST_MAC_OCTET;
    }

	// Actualizam datele antetului ARP
	init_arp_header(arp_hdr);
    arp_hdr->op = htons(ARP_REQUEST);
	arp_hdr->spa = inet_addr(get_interface_ip(entry->interface));
	arp_hdr->tpa = entry->next_hop;
    memcpy(arp_hdr->sha, eth_hdr->ether_shost, MAC_SIZE);
    for (int i = 0; i < MAC_SIZE; i++) {
        arp_hdr->tha[i] = 0;
    }

	// Trimitem pachetul
	send_to_link(entry->interface, arp_packet, ARP_LEN);
}


// Functie care trimite un pachet de tip ARP Reply
void send_arp_reply(char *received_arp, int interface, uint8_t *int_mac) {
    eth_header *eth_hdr = (eth_header *)received_arp;
    arp_header *arp_hdr = (arp_header *)(received_arp + sizeof(eth_header));
    // size_t total_len = sizeof(eth_header) + sizeof(arp_header);

    // setam tipul ARP Reply
    arp_hdr->op = htons(ARP_REPLY);

    // schimbam adresele IP (nu folosim functia "swap_ip_addresses" pentru
    // a nu fi nevoiti sa accesam membrii din structura "packed")
    uint32_t aux_ip = arp_hdr->spa;
    arp_hdr->spa = arp_hdr->tpa;
    arp_hdr->tpa = aux_ip;

    // schimbam adresele MAC
    memcpy(arp_hdr->tha, arp_hdr->sha, MAC_SIZE);
    memcpy(arp_hdr->sha, int_mac, MAC_SIZE);
    memcpy(eth_hdr->ether_dhost, arp_hdr->tha, MAC_SIZE);
    memcpy(eth_hdr->ether_shost, arp_hdr->sha, MAC_SIZE);

    // trimitem pachetul
    send_to_link(interface, received_arp, ARP_LEN);
}

// Functie care trimite pachetele aflate in asteptare din cauza unei adrese MAC necunoscute
void send_waiting_packets(queue *q_wait, arp_table *arp_table, uint32_t ipaddr, uint8_t *found_mac) {
    queue new_q = queue_create();
    DIE(new_q == NULL, "malloc");
    waiting_packet *packet;
    eth_header *eth_hdr;

    // scoatem pachetele din coada si le trimitem daca adresa IP corespunde
    while (!queue_empty(*q_wait)) {
        packet = (waiting_packet*)queue_deq(*q_wait);
        eth_hdr = (eth_header*)packet->buffer;

        // daca adresa IP corespunde, trimitem pachetul
        if (packet->next_hop_ip == ipaddr) {
            memcpy(eth_hdr->ether_dhost, found_mac, 6);
            send_to_link(packet->interface, packet->buffer, packet->packet_len);         
            free(packet);
        } else {
            // daca adresa IP nu corespunde, punem pachetul in noua coada
            queue_enq(new_q, (void*)packet);
        }
    }
    // actualizam coada veche
    *q_wait = new_q;
}