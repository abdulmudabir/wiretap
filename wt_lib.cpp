
// include declarations written in header corresponding to this file
#include "wt_lib.h"

// include standard libraries
#include <iostream>
#include <cstdio>
#include <cstring>
#include <getopt.h>

/* default constructor for class ArgsParser */
ArgsParser::ArgsParser() {
	memset(this.filename, 0x00, sizeof(this.filename));	// initially zero-out contents of filename
	
}

/* parameterized constructor for class ArgsParser 
 * sets filename 
 */
ArgsParser::ArgsParser(char *str) {
	// memset(this.filename, 0x00, sizeof(this.filename));
	memcpy(this.filename, str, strlen(str));	// register filename provided at cli
}

void ArgsParser::usage(FILE *f) {
	fprintf(f, "
				wiretap [OPTIONS] file.pcap\n
					-h or --help				Print this help screen\n
					-v or --verbose				verbose flag, print additional information\n
					--open						Open a packet capture file\n
		");
}

/*
 * parse_args() -> void
 * function that parses command line arguments to 'wiretap'
 */
void ArgsParser::parse_args(int argc, char *argv[], ArgsParser wt_args) {

    int g;	// grab return value of getopt_long()
    int option_index;	// array index that getopt_long() shall set
    while ( (g = getopt_long(argc, argv, "ho", long_options, &option_index)) != -1) {
    	switch(g) {
    		case 'h':
    			wt_args.usage(stdout);
    			break;
    		case 'v':
    			verbose_flag = 1;
    			break;
    		case 'o':
    			wt_args = wt_args(optarg);
    			break;
    		default:
 				wt_args.usage(stdout);
    			break;   			
    	}
    }
}