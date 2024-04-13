#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "constants.h"
#include "router_helper.h"
#include "struct_helper.h"

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	uint8_t router_mac_address[6];
	uint32_t router_ip_address;
	int nr_ip_entries;
	route_table_entry *rtable;
	trie_node *root_rtree = create_trie_node();
	arp_table *arptable = create_arp_table();
	queue q_wait = queue_create();
	// arp_table_entry *temp_arptable;
	// int temp_arptable_size = 6;

	// fisierul arp_table_temp.txt nu mai este necesar
	// temp_arptable = malloc(sizeof(arp_table_entry) * (temp_arptable_size + 1));
	// DIE(temp_arptable == NULL, "malloc");
	// parse_arp_table("arp_table_temp.txt", temp_arptable);	

	// alocam memorie pentru tabela de rutare
	rtable = malloc(sizeof(route_table_entry) * MAX_RTABLE_SIZE);
	DIE(rtable == NULL, "malloc");

	// pregatim tabela de rutare
	nr_ip_entries = read_rtable(argv[1], rtable);
	for (int i = 0; i < nr_ip_entries; i++) {
		add_route_to_trie(root_rtree, &rtable[i]);
	}

	// aflam adresa IP a router-ului si adresa MAC
	router_ip_address = inet_addr(get_interface_ip(THIS_DEVICE_INTERFACE));
	get_interface_mac(THIS_DEVICE_INTERFACE, router_mac_address);

	while (1) {
		int interface;
		size_t len;
		uint8_t int_mac[6];

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		get_interface_mac(interface, int_mac);	

		int is_for_router;
		if (memcmp(eth_hdr->ether_dhost, int_mac, MAC_SIZE) == 0) {
			is_for_router = 1;
		} else {
			is_for_router = 0;
		}
		// verificam daca pachetul trebuie interpretat de router
		if (!is_broadcast_mac(eth_hdr->ether_dhost) && !is_for_router) {		
			continue;
		}

		// verificam daca pachetul este de tip IP sau ARP
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			ip_header *ip_hdr = (ip_header*) (buf + sizeof(struct ether_header));
			uint32_t dest_ip = ip_hdr->daddr;
			
			// verificam daca pachetul este pentru router
			if (dest_ip == router_ip_address) {
				// daca pachetul este pentru router, trimitem un mesaj de tip ICMP Echo Reply
				send_echo_reply(buf, interface);
				continue;
			}

			// Verificam checksum-ul pachetului primit
			if (!verify_checksum((uint16_t*)ip_hdr, sizeof(ip_header), (uint16_t*)(&ip_hdr->check))) {
				continue;
			}

			if (ip_hdr->ttl <= 1) {
				// trimitem un mesaj de tip ICMP Time Exceeded
				send_error_packet(buf, interface, TYPE_TIME_EXCEEDED, router_mac_address, router_ip_address);
				continue;
			}
			ip_hdr->ttl--;

			// cautam cea mai buna ruta pentru destinatie in trie
			route_table_entry *best_route = get_best_route_from_trie(root_rtree, dest_ip);
			if (best_route == NULL) {
				// daca nu exista o ruta valida, trimitem un mesaj de tip ICMP Destination Unreachable
				send_error_packet(buf, interface, TYPE_DEST_UNREACH, router_mac_address, router_ip_address);
				continue;
			}

			// Recalculam checksum-ul pachetului primit (ttl-ul a fost decrementat)
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(ip_header)));

			// rescriem adresa MAC a router-ului ca sursa
			memcpy(eth_hdr->ether_shost, router_mac_address, MAC_SIZE);

			// temp_get_mac_from_arp_table(best_route->next_hop, temp_arptable, temp_arptable_size, eth_hdr->ether_dhost);
			// verificam daca avem adresa MAC pentru urmatorul hop
			if (get_arp_table_entry(arptable, best_route->next_hop, eth_hdr->ether_dhost) == 0) {
				void *waiting_packet = prep_waiting_packet(buf, best_route->next_hop, best_route->interface);
				// adaugam pachetul in lista de asteptare
				queue_enq(q_wait, waiting_packet);

				// trimitem un mesaj de tip ARP Request
				send_arp_request(best_route);
				continue;
			} else {
				// trimitem pachetul mai departe
				send_to_link(best_route->interface, buf, len);
				continue;
			}			
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			arp_header *arp_hdr = (arp_header*) (buf + sizeof(eth_header));

			if (ntohs(arp_hdr->op) == ARP_REQUEST) {
				if (arp_hdr->tpa == router_ip_address) {
					// daca pachetul este pentru router, trimitem un mesaj de tip ARP Reply
					send_arp_reply(buf, interface, int_mac);
					continue;
				}
			} else if (ntohs(arp_hdr->op) == ARP_REPLY) {
				// adaugam adresa MAC in tabela ARP
				add_arp_table_entry(arptable, arp_hdr->spa, arp_hdr->sha);
				// trimitem pachetele aflate in asteptare
				send_waiting_packets(&q_wait, arptable, arp_hdr->spa, arp_hdr->sha);
				continue;
			}
		} else {
			// daca nu este nici de tip IP, nici de tip ARP, ignoram pachetul
			continue;
		}
	}

	// eliberam memoria alocata
	while (!queue_empty(q_wait)) {
		waiting_packet *wp = (waiting_packet*)queue_deq(q_wait);
		free(wp);
	}
	free(arptable->entries);
	free(arptable);
	free(rtable);
	free_trie(root_rtree);
	// free(temp_arptable);
}
