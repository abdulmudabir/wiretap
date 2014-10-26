
#include <iostream>
using namespace std;

#include "wt_lib.h"

int extern a;

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

	ArgsParser wt_args;
	wt_args.parse_args(argc, argv);

	pcap_t pcap_open_offline()


	return 0;
}