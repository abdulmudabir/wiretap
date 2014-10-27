
// include declarations written in header corresponding to this file
#include "wt_lib.h"

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
	// memset(this.filename, 0x00, sizeof(this.filename));
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

inline char * ArgsParser::get_filename() {
	return this->filename;
}

/*
 * parse_args() -> void
 * function that parses command line arguments to 'wiretap'
 */
void ArgsParser::parse_args(int argc, char *argv[], ArgsParser wt_args) {

    int g;	// grab return value of getopt_long()
    int option_index;	// array index that getopt_long() shall set
    while ( (g = getopt_long(argc, argv, "ho:v", long_options, &option_index)) != -1) {
    	switch(g) {
    		case 'h':
    			wt_args.usage(stdout);
    			break;
    		case 'v':
    			verbose_flag = 1;
    			break;
    		case 'o':
    			wt_args = ArgsParser(optarg);
    			break;
    		default:
 				wt_args.usage(stdout);
    			exit(1);   			
    	}
    }

}