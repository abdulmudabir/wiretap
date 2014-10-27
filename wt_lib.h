
/* 
 * references:
 	http://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
 */

#ifndef _WT_LIB_H_
#define _WT_LIB_H_

static int verbose_flag = 0;

static struct option long_options[] = {
	{"help",	no_argument,       0, 'h'},
	{"verbose", no_argument,       &verbose_flag, 1}, 
	{"open",    required_argument, 0, 'o'},
	{0, 0, 0, 0}	// last element needs to be filled as all zeros
};

class ArgsParser {
	private:
		char filename[100];
	public:
		ArgsParser();	// default constructor
		ArgsParser(char *);	// parameterized constructor
		void usage(FILE *);
		void parse_args(int, char **, ArgsParser);
};

#endif