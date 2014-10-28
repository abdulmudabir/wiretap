
/* 
 * references:
 	http://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
 */

#ifndef _WT_LIB_H_
#define _WT_LIB_H_

#include <cstdio>
#include <getopt.h>
#include "/usr/include/pcap/pcap.h"	// standard pcap library

class ArgsParser {
	private:
		char filename[100];
	public:
		ArgsParser();	// default constructor
		ArgsParser(char *);	// parameterized constructor
		void usage(FILE *);	// instructs on using program options
		void parse_args(int, char **, ArgsParser **);	// scans through cli arguments
		char * get_filename();	// retrieve packet capture filename
};

void pcap_callback(u_char *, const struct pcap_pkthdr*, const u_char *);

#endif