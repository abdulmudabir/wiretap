
#include <iostream>
#include <cstdlib>
using namespace std;

#include "wt_lib.h"

// include all packet capture helper libraries
#include "/usr/include/netinet/ip.h"
#include "/usr/include/netinet/udp.h"
#include "/usr/include/net/if_arp.h"
#include "/usr/include/arpa/inet.h"
#include "/usr/include/pcap/bpf.h"


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
		cout << "========= Link layer =========" << endl << endl;
		cout << "--------- Source ethernet addresses ---------" << endl << endl;
		pcap_loop(pcp, -1, pcap_callback, NULL);	// loop through each packet until all packets are parsed
		print_map(src_ethaddr_map);
		cout << endl << endl;
		cout << "--------- Destination ethernet addresses ---------" << endl << endl;
		print_map(dest_ethaddr_map);

		pcap_close(pcp);	// close packet capture file
	}

	// release object memory
	delete wt_args;

	return 0;
}