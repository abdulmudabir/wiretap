
/*
 * References:
 	http://www.binarytides.com/code-packet-sniffer-c-winpcap/
 */

// standard libraries
#include <iostream>
#include <cstdlib>
#include <iomanip>

using namespace std;

#include "wt_lib.h"

// include all packet capture helper libraries
#include "/usr/include/netinet/ip.h"
#include "/usr/include/netinet/udp.h"
#include "/usr/include/arpa/inet.h"
#include "/usr/include/pcap/bpf.h"
#include "/usr/include/linux/if_ether.h"

/******************** declare global variables *************************/

//---------- ethernet address maps ---------------------------------------------------
map<std::string, int> src_ethaddr_map;	// "ordered map" to store source ethernet addresses
map<std::string, int> dst_ethaddr_map;	// "ordered map" to store destination ethernet addresses
//-------------------------------------------------------------------------------------
map<std::string, int>::iterator itr;	// iterator to iterate over elemnents in a map
//---------- IP address maps ---------------------------------------------------
map<std::string, int> src_ipaddr_map;	// to store source IP addresses
map<std::string, int> dst_ipaddr_map;	// to store destination IP addresses
//-----------ARP header --------------------------------------------------------------
typedef struct {
	unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
	unsigned char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char __ar_sip[4];		/* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char __ar_tip[4];		/* Target IP address.  */
}arp_hdr_t;

map<std::string, int> arp_map;	// to hold ARP packet info
//-----------TCP header --------------------------------------------------------------
typedef struct {
	u_int16_t th_sport;		/* source port */
    u_int16_t th_dport;		/* destination port */
    u_int32_t th_seq;		/* sequence number */
    u_int32_t th_ack;		/* acknowledgement number */
	u_int8_t th_flags;
	#define TH_FIN	0x01
	#define TH_SYN	0x02
	#define TH_RST	0x04
	#define TH_PUSH	0x08
		#define TH_ACK	0x10
	#define TH_URG	0x20

    u_int16_t th_win;		/* window */
    u_int16_t th_sum;		/* checksum */
    u_int16_t th_urp;		/* urgent pointer */
}tcphdr_t;

map<std::string, int> tcp_sportmap;	// to hold tcp source ports
/******************** end global variables declaration *************************/

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

	if (pcap_datalink(pcp) != DLT_EN10MB) {	// capture ethernet device packets and none other
		fprintf(stderr, "Ethernet device packets not found. Program proceeding to termination.\n");
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
		cout << "\n" << "=============== Network layer ===============" << endl << endl;
		cout << "------ Network layer protocols ------" << endl << endl;
		cout << "------ Source IP addresses ------" << endl << endl;
		print_map(src_ipaddr_map);
		cout << endl;
		cout << "------ Destination IP addresses ------" << endl << endl;
		print_map(dst_ipaddr_map);
		cout << endl;
		cout << "------ Unique ARP participants ------" << endl << endl;
		print_map(arp_map);
		cout << endl;
		cout << "\n" << "=============== Transport layer ===============" << endl << endl;
		cout << "------ Transport layer protocols ------" << endl << endl;
		cout << "------ Transport layer: TCP ------" << endl << endl;
		cout << "------ Source TCP ports ------" << endl << endl;
		print_map(tcp_sportmap);
		cout << "------ Destination TCP ports ------" << endl << endl;
		cout << "------ TCP flags ------" << endl << endl;

		pcap_close(pcp);	// close packet capture file
	}

	// release object memory
	delete wt_args;

	return 0;
}

void pcap_callback(u_char *user, const struct pcap_pkthdr* phdr, const u_char *packet) {
	
	u_char* pack_data;	// contents of the packet

	/********* parse header types *********/
	parse_hdrs(packet);

}

/*
 * parse_hdrs() -> void
 * 		parses the different header-types in the packet
 * function argument 'const u_char *pkt' is a pointer to the start of the packet header (ETH)
 */
void parse_hdrs(const u_char *pkt) {

	char buf[40];	// char array buffer to hold strings
	memset(buf, 0x00, sizeof(buf));	// zero-out buffer initially

	//-------------------- ETH header parsing ------------------------------------------

	struct ethhdr *eth_hdr = (struct ethhdr *) pkt;	// cast packet to ethernet header type
	
	/* get source Ethernet address as a string */
	snprintf(buf, 40, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2], eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
	string eth_address_src(buf);	// convert char array to string

	/* now, get destination Ethernet address as a string */
	memset(buf, 0x00, sizeof(buf));	// flush-out buffer for reuse
	snprintf(buf, 40, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2], eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);
	string eth_address_dst(buf);

	/* insert source eth addr & destination eth addr in their respective "ordered map"s */
	mapping_elems(eth_address_src, src_ethaddr_map);
	mapping_elems(eth_address_dst, dst_ethaddr_map);
		
	//-------------------- end ETH header parsing -------------------------------------

	//-------------------- IP header parsing ------------------------------------------

	struct iphdr *ip_hdr = (struct iphdr *) (pkt + ETH_HLEN);	// get a pointer to IP header type
	arp_hdr_t *arp_hdr = (arp_hdr_t *) ip_hdr;	// cast iphdr to arp header type

	if (ntohs(eth_hdr->h_proto) == ETH_P_IP) {	// only account for IPv4 packets
		string src_ipaddr( inet_ntoa( *(struct in_addr *) &ip_hdr->saddr ) );	// convert u_int32_t to dotted IP addr string
		mapping_elems(src_ipaddr, src_ipaddr_map);	// have a unique count of src IP addr in a map
		string dst_ipaddr( inet_ntoa( *(struct in_addr *) &ip_hdr->daddr) );	// destination IP addr like done for src IP addr
		mapping_elems(dst_ipaddr, dst_ipaddr_map);
	} else if (ntohs(eth_hdr->h_proto) == ETH_P_ARP) { 	//----------------- ARP packet parsing -------------------------

		memset(buf, 0x00, sizeof(buf));	// flush-out buffer
		snprintf(buf, 40, "%02x:%02x:%02x:%02x:%02x:%02x", arp_hdr->__ar_sha[0], arp_hdr->__ar_sha[1], arp_hdr->__ar_sha[2], arp_hdr->__ar_sha[3], arp_hdr->__ar_sha[4], arp_hdr->__ar_sha[5]);	// each octet byte written in hex
		string sha(buf);	// char array to string

		memset(buf, 0x00, sizeof(buf));	// flush out buffer for reuse
		snprintf(buf, 40, "%d.%d.%d.%d", arp_hdr->__ar_sip[0], arp_hdr->__ar_sip[1], arp_hdr->__ar_sip[2], arp_hdr->__ar_sip[3]);	// grab sender IP address octets
		string arp_ip(buf);

		memset(buf, 0x00, sizeof(buf));
		snprintf( buf, 40, "%s / %s", sha.c_str(), arp_ip.c_str() );	// sender hardware address along with sender IP address
		string mac_ip(buf);
		mapping_elems(mac_ip, arp_map);	// insert into hash map
		//-------------------------------- end ARP parsing -------------------------------------------------------------

	}
	//-------------------- end IP header parsing ------------------------------------------

	//-------------------- TCP header parsing ---------------------------------------------

	tcphdr_t *tcp_hdr = (tcphdr_t *) (pkt + ETH_HLEN + sizeof(ip_hdr));	// get pointer to TCP header in packet
	
	// parse differently for different protocols

	memset(buf, 0x00, sizeof(buf));
	snprintf(buf, 40, "%d", tcp_hdr->th_sport);
	string sport_str(buf);
	mapping_elems(sport_str, tcp_sportmap);

	//-------------------- end TCP header parsing -----------------------------------------

}

/* 
 * mapping_ethaddr() -> void
 * 	inserts every source/destination ethernet addresses in a map
 */
void mapping_elems(string elem, map<string, int> &hmap) {
	if ( (itr = hmap.find(elem)) == hmap.end() )	// src eth addr is not already present in map
		hmap.insert( pair<string, int>(elem, 1) );	// insert new src eth addr & set its count to 1 initially
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