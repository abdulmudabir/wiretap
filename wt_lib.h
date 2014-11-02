
/* 
 * references:
 	http://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
 */

#ifndef _WT_LIB_H_
#define _WT_LIB_H_

#include <cstdio>
#include <getopt.h>
#include <string>
#include <cstring>
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

/* pcap_loop()'s callback routine */
void pcap_callback(u_char *, const struct pcap_pkthdr*, const u_char *);

/* parse_hdrs() parses different header-types in a packet */
void parse_hdrs(const u_char *);

/* mapping_ethaddr() inserts every source/destination ethernet addresses in a map */
void mapping_elems(std::string, std::map<std::string, int> &);

/* print_map() prints contents of any map passed as argument */
void print_map(std::map<std::string, int> &);

#endif