
/*
 * References:
 	* https://code.google.com/p/pcapsctpspliter/issues/detail?id=6
	* "Hacking: The Art of Exploitation, 2nd Edition" book
 */

// include declarations written in header corresponding to this file
#include "wt_lib.h"

// packet capture libraries
#include "/usr/include/netinet/ether.h"
#include "/usr/include/linux/if_ether.h"

// include standard libraries
#include <iostream>
#include <cstdio>
#include <cstring>
#include <string>
#include <getopt.h>
#include <cstdlib>
#include <map>
#include <utility>

using namespace std;

static int verbose_flag = 0;	// verbose mode

// enter long options to be used at cli
static struct option long_options[] = {
	{"help",	no_argument,       0, 'h'},
	{"verbose", no_argument,       0, 'v'}, 
	{"open",    required_argument, 0, 'o'},
	{0, 0, 0, 0}	// last element needs to be filled as all zeros
};

/* default constructor for class PacketParser */
PacketParser::PacketParser() {
	memset(this->filename, 0x00, sizeof(this->filename));	// initially zero-out contents of filename
}

/* parameterized constructor for class PacketParser 
 * sets filename 
 */
PacketParser::PacketParser(char *str) {
	memset(this->filename, 0x00, sizeof(this->filename));	// for case when default constructor is not called
	memcpy(this->filename, str, strlen(str));	// register filename provided at cli
}

void PacketParser::usage(FILE *file) {
	if (file == NULL)
		file = stdout;	// set standard output by default

	fprintf(file, "wiretap [OPTIONS] example.pcap\n"
				"	-h or --help			Print this help screen\n"
				"	-v or --verbose 		verbose flag, print additional information\n"
				"	--open example.pcap 		Open packet capture file 'example.pcap'\n");
}

char * PacketParser::get_filename() {
	return this->filename;
}

/*
 * parse_args() -> void
 * function that parses command line arguments to 'wiretap'
 */
void PacketParser::parse_args(int argc, char *argv[], PacketParser **wt_args) {	// pass PacketParser pointer-to-pointer to reach memory allocated in this function

    int g;	// grab return value of getopt_long()
    int option_index;	// array index that getopt_long() shall set
    while ( (g = getopt_long(argc, argv, "ho:v", long_options, &option_index)) != -1) {
    	switch(g) {
    		case 'h':
    			(*wt_args)->usage(stdout);
    			break;
    		case 'v':
    			verbose_flag = 1;
    			break;
    		case 'o':
    			*wt_args = new PacketParser(optarg);
    			break;
    		default:
 				(*wt_args)->usage(stdout);
    			exit(1);   			
    	}
    }

}

void pcap_callback(u_char *user, const struct pcap_pkthdr* phdr, const u_char *packet) {
	
	int pkt_length;	// length of the packet
	int tcp_header_len;	// length of tcp header
	int total_header_len;	// total length of accounting all headers

	u_char* pack_data;	// contents of the packet

	/***** parse ethernet header-type *****/
	parse_ethernet(packet, src_ethaddr_map, dest_ethaddr_map);

}

/*
 * parse_ethernet() -> void
 * 		parses the ethernet header-type content in the packet
 * function argument 'const u_char *pkt' is a pointer to the start of the packet header (ETH)
 */
void parse_ethernet(const u_char *pkt, map<string, int> &src_map, map<string, int> &dest_map) {

	struct ethhdr *eth_hdr = (struct ethhdr *) pkt;	// cast packet to ethernet header type
	
	char eth_address[20];	// to store each unique Ethernet address
	memset(eth_address, 0x00, sizeof(eth_address));	// zero-out char array initially
	char colon[] = ":";
	
	/* construct source Ethernet address */
	for (int i = 0; i < ETH_ALEN; i++) {
		sprintf( (eth_address + 3 * i), "%02x", *(eth_hdr->h_source + i) );	// fetch source address from ethhdr structure
		if ( i < (ETH_ALEN - 1) )
			memcpy( (eth_address + 2 + 3 * i), colon, 1 );	// insert colons between each octet except at the last 
	}
	string eth_address_src(eth_address);	// convert char array to string (use string constructor)

	/* now, construct destination Ethernet address */
	memset(eth_address, 0x00, sizeof(eth_address));	// first, flush out address holder
	for (int i = 0; i < ETH_ALEN; i++) {
		sprintf( (eth_address + 3 * i), "%02x", *(eth_hdr->h_dest + i) );	// fetch destination address from ethhdr structure
		if ( i < (ETH_ALEN - 1) )
			memcpy( (eth_address + 2 + 3 * i), colon, 1 );	// insert colons between octets	
	}
	string eth_address_dest(eth_address);	// destination eth addr string

	/* insert source eth addr in an 'ordered' map */
	if ( (itr = src_map.find(eth_address_src)) == src_map.end() ) {	// if src eth addr was not present in map already ...
		src_map.insert( pair<string, int>(eth_address_src, 1) );	// insert src eth addr in map with its initial count = 1
	} else
		itr->second++;	// increase count of already present src eth addr

	/* now, insert destination eth addr in its respective map like above */
	if ( ( itr = dest_map.find(eth_address_dest) ) == dest_map.end() )
		dest_map.insert( pair<string, int>(eth_address_dest, 1) );
	else
		itr->second++;
}

/*
 * print_map() -> void
 * 
 */
 void print_map(map<std::string, int> &somemap) {
 	map<string, int>::iterator itr;	// iterator to iterate over map
 	for ( itr = somemap.begin(); itr != somemap.end(); itr++)
 		cout << itr->first << "\t\t" << itr->second << endl;
 }