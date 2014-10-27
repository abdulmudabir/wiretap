
#include <iostream>
using namespace std;

#include "wt_lib.h"

// include all packet capture helper libraries
#include "/usr/include/netinet/ether.h"
#include "/usr/include/netinet/ip.h"
#include "/usr/include/netinet/udp.h"
#include "/usr/include/net/if_arp.h"
#include "/usr/include/arpa/inet.h"
#include "/usr/include/linux/if_ether.h"
#include "/usr/include/pcap/bpf.h"
#include "/usr/include/pcap/pcap.h"

int main(int argc, char *argv[]) {

	ArgsParser *wt_args = NULL;	// assign to NULL to avoid "uninitialization" warning
	wt_args->parse_args(argc, argv, &wt_args);	// parse command-line arguments

	// pcap_t pcap_open_offline()
	cout << "testing in main, Filename: " << wt_args->get_filename() << endl;

	delete wt_args;

	return 0;
}