
// standard libraries
#include <iostream>
#include <cstdlib>
#include <iomanip>

using namespace std;

#include "wt_lib.h"

// include all packet capture helper libraries
#include "/usr/include/netinet/ip.h"
#include "/usr/include/netinet/udp.h"
#include "/usr/include/net/if_arp.h"
#include "/usr/include/arpa/inet.h"
#include "/usr/include/pcap/bpf.h"
#include "/usr/include/linux/if_ether.h"

/***** declare global variables ******/
map<std::string, int> src_ethaddr_map;	// "ordered map" to store source ethernet addresses
map<std::string, int> dst_ethaddr_map;	// "ordered map" to store destination ethernet addresses
map<std::string, int>::iterator itr;	// iterator to iterate over elemnents in a map

int main(int argc, char *argv[]) {

	PacketParser *wt_args = NULL;	// assign to NULL to avoid "uninitialization" warning
	wt_args->parse_args(argc, argv, &wt_args);	// parse command-line arguments


	char errbuf[PCAP_ERRBUF_SIZE];	// stores error text when pcap_open_offline() fails
	pcap_t *pcp = pcap_open_offline(wt_args->get_filename(), errbuf);	// open given packet capture file
	if (!pcp) {	// check if packet capture file was unsuccessful just in case
		cerr << "Could not open packet capture file: " << wt_args->get_filename() << endl;
		wt_args->usage(stderr);
		exit(1);
	}

	if (pcap_datalink(pcp) != DLT_EN10MB) {	// look for link-layer header type - Ethernet and none other
		fprintf(stderr, "Ethernet headers not found. Program proceeding to termination.\n");
		exit(1);
	} else {

		// first, get set to display link layer content in packet
		cout << endl << setfill('*') << setw(80) << "\n\n";
		cout << "=============== Link layer ===============" << endl << endl;
		cout << "------ Source ethernet addresses ------" << endl << endl;
		pcap_loop(pcp, -1, pcap_callback, NULL);	// loop through each packet until all packets are parsed
		print_map(src_ethaddr_map);
		cout << endl;
		cout << "------ Destination ethernet addresses ------" << endl << endl;
		print_map(dst_ethaddr_map);

		// now display network layer content in packet
		cout << "\n\n" << "=============== Network layer ===============" << endl << endl;
		cout << "------ Network layer protocols ------" << endl << endl;


		pcap_close(pcp);	// close packet capture file
	}

	// release object memory
	delete wt_args;

	return 0;
}

void pcap_callback(u_char *user, const struct pcap_pkthdr* phdr, const u_char *packet) {
	
	int pkt_length;	// length of the packet
	int tcp_header_len;	// length of tcp header
	int total_header_len;	// total length of accounting all headers

	u_char* pack_data;	// contents of the packet

	/***** parse ethernet header-type *****/
	parse_ethernet(packet);

}

/*
 * parse_ethernet() -> void
 * 		parses the ethernet header-type content in the packet
 * function argument 'const u_char *pkt' is a pointer to the start of the packet header (ETH)
 */
void parse_ethernet(const u_char *pkt) {

	struct ethhdr *eth_hdr = (struct ethhdr *) pkt;	// cast packet to ethernet header type
	
	/* get source Ethernet address as a string */
	string eth_address_src = cons_ethaddr(eth_hdr->h_source);

	/* now, get destination Ethernet address as a string */
	string eth_address_dst = cons_ethaddr(eth_hdr->h_dest);

	/* insert source eth addr & destination eth addr in their respective "ordered map"s */
	mapping_ethaddr(eth_address_src, src_ethaddr_map);
	mapping_ethaddr(eth_address_dst, dst_ethaddr_map);

}

/*
 * cons_ethaddr() -> string
 * constructs Ethernet address from an instance of ethernet header-type (struct)
 */
string cons_ethaddr(unsigned char *h_addr) {
	char eth_address[20];	// to store ethernet address
	memset(eth_address, 0x00, sizeof(eth_address));	// zero-out char array initially
	char colon[] = ":";	// to insert colon between octets in an ethernet address

	for (int i = 0; i < ETH_ALEN; i++) {
		sprintf( (eth_address + 3 * i), "%02x", *(h_addr + i) );	// fetch destination address from ethhdr structure
		if ( i < (ETH_ALEN - 1) )
			memcpy( (eth_address + 2 + 3 * i), colon, 1 );	// insert colons between octets			
	}
	string eth_address_str(eth_address);	// convert char array to string (use string constructor)

	return eth_address_str;	// return construct ethernet address
}

/* 
 * mapping_ethaddr() -> void
 * 	inserts every source/destination ethernet addresses in a map
 */
void mapping_ethaddr(string eaddr, map<string, int> &emap) {
	if ( (itr = emap.find(eaddr)) == emap.end() )	// src eth addr is not already present in map
		emap.insert( pair<string, int>(eaddr, 1) );	// insert new src eth addr & set its count to 1 initially
	else	// if src eth addr already present in map
		itr->second++;	// increase its count
}

/*
 * print_map() -> void
 * 	function prints contents of any map passed as argument
 */
 void print_map(map<string, int> &anymap) {
 	for ( itr = anymap.begin(); itr != anymap.end(); itr++)
 		cout << itr->first << "\t\t" << itr->second << endl;
 }