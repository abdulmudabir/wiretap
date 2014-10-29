
/* 
 * references:
 	http://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
 */

#ifndef _WT_LIB_H_
#define _WT_LIB_H_

#include <cstdio>
#include <getopt.h>
#include <string>
#include <map>
#include "/usr/include/pcap/pcap.h"	// standard pcap library

class PacketParser {
	private:
		char filename[100];
	public:
		PacketParser();	// default constructor
		PacketParser(char *);	// parameterized constructor
		void usage(FILE *);	// instructs on using program options
		void parse_args(int, char **, PacketParser **);	// scans through cli arguments
		char * get_filename();	// retrieve packet capture filename
};

static std::map<std::string, int> src_ethaddr_map;
static std::map<std::string, int> dst_ethaddr_map;
static std::map<std::string, int>::iterator itr;

/* pcap_loop()'s callback routine */
void pcap_callback(u_char *, const struct pcap_pkthdr*, const u_char *);

/* parse_ethernet() parses ethernet header-type content in a packet */
void parse_ethernet(const u_char *);

/* cons_ethaddr() constructs Ethernet address from an instance of ethernet header-type (struct) */
std::string cons_ethaddr(unsigned char *);

/* cons_ethaddr() constructs Ethernet address from an instance of ethernet header-type (struct) */
void mapping_ethaddr(std::string, std::map<std::string, int> &);

void print_map(std::map<std::string, int> &);

#endif