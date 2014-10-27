
/* 
 * references:
 	http://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
 */

#ifndef _WT_LIB_H_
#define _WT_LIB_H_

#include <cstdio>
#include <getopt.h>

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

#endif