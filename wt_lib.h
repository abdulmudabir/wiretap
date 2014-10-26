
#ifndef _WT_LIB_H_
#define _WT_LIB_H_

class ArgsParser {
	private:
		char filename[100];
	public:
		ArgsParser();	// default constructor
		ArgsParser(char *);	// parameterized constructor
		void parse_args(int, char **, ArgsParser);
};

#endif