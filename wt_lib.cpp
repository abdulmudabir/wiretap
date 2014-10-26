
// include declarations written in header corresponding to this file
#include "wt_lib.h"

// include standard libraries
#include <unistd.h>
#include <cstring>

/* default constructor for class ArgsParser */
ArgsParser::ArgsParser() {
	memset(this.filename, 0x00, sizeof(this.filename));	// initially zero-out contents of filename
	
}

/* parameterized constructor for class ArgsParser 
 * sets filename 
 */
ArgsParser::ArgsParser(char *str) {
	memset(this.filename, 0x00, sizeof(this.filename));
	memcpy(this.filename, str, strlen(str));	// register filename provided at cli
}

/*
 * parse_args() -> void
 * function that parses command line arguments to 'wiretap'
 */
void ArgsParser::parse_args(int argc, char *argv[], ArgsParser wt_args) {

	int g;
	while( (g = getopt(argc, argv, "hr:v")) != -1 ) {
		switch(g) {
			case 'h':	// display program usage information
				usage(stdout);
				break;
			case 'r':	// read from file
				wt_args = ArgsParser(optarg);
				break;
		}
	}		
}