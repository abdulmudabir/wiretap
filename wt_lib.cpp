
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
#include <getopt.h>
#include <cstdlib>

using namespace std;

static int verbose_flag = 0;	// verbose mode

// enter long options to be used at cli
static struct option long_options[] = {
	{"help",	no_argument,       0, 'h'},
	{"verbose", no_argument,       0, 'v'}, 
	{"open",    required_argument, 0, 'o'},
	{0, 0, 0, 0}	// last element needs to be filled as all zeros
};

/* default constructor for class ArgsParser */
ArgsParser::ArgsParser() {
	memset(this->filename, 0x00, sizeof(this->filename));	// initially zero-out contents of filename
}

/* parameterized constructor for class ArgsParser 
 * sets filename 
 */
ArgsParser::ArgsParser(char *str) {
	memset(this->filename, 0x00, sizeof(this->filename));	// for case when default constructor is not called
	memcpy(this->filename, str, strlen(str));	// register filename provided at cli
}

void ArgsParser::usage(FILE *file) {
	if (file == NULL)
		file = stdout;	// set standard output by default

	fprintf(file, "wiretap [OPTIONS] example.pcap\n"
				"	-h or --help			Print this help screen\n"
				"	-v or --verbose 		verbose flag, print additional information\n"
				"	--open example.pcap 		Open packet capture file 'example.pcap'\n");
}

char * ArgsParser::get_filename() {
	return this->filename;
}

/*
 * parse_args() -> void
 * function that parses command line arguments to 'wiretap'
 */
void ArgsParser::parse_args(int argc, char *argv[], ArgsParser **wt_args) {	// pass ArgsParser pointer-to-pointer to reach memory allocated in this function

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
    			*wt_args = new ArgsParser(optarg);
    			break;
    		default:
 				(*wt_args)->usage(stdout);
    			exit(1);   			
    	}
    }

}

void parse_ethernet(const u_char *);

void pcap_callback(u_char *user, const struct pcap_pkthdr* phdr, const u_char *packet) {
	
	int pkt_length;	// length of the packet
	int tcp_header_len;	// length of tcp header
	int total_header_len;	// total length of accounting all headers

	u_char* pack_data;	// contents of the packet

	parse_ethernet(packet);	// parse ethernet header-type
	// ETH_HDR_SIZE, 

}

/*
 * parse_ethernet() -> void
 * 		parses the ethernet header-type content in the packet
 * function argument 'const u_char *pkt' is a pointer to the start of the packet header (ETH)
 */
void parse_ethernet(const u_char *pkt) {

/*	struct ethhdr *eth_hdr = (struct ethhdr *) pkt;	// cast packet to ethernet header type
	
	unsigned char eth_address[20];	// to store each unique Ethernet address
	memset(eth_address, 0x00, sizeof(eth_address));	// zero-out char array initially
	
	cout << "========= Link layer =========" << endl << endl;
	cout << "--------- Source ethernet addresses ---------" << endl << endl;

	 display unique source as well as destination Ethernet addresses 
	along with counts of all packets those unique Ethernet addresses occur in 


	printf("[ Source: %02x", ethernet_header->ether_src_addr[0]);
		for(i=1; i < ETHER_ADDR_LEN; i++)
			printf(":%02x", ethernet_header->ether_src_addr[i]);
		printf("\tDest: %02x", ethernet_header->ether_dest_addr[0]);
		for(i=1; i < ETHER_ADDR_LEN; i++)
			printf(":%02x", ethernet_header->ether_dest_addr[i]);
		printf("\tType: %hu ]\n", ethernet_header->ether_type);*/
}
