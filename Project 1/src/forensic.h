#ifndef _FORENSIC_H
#define _FORENSIC_H

#define OPTION_1 "-r"
#define OPTION_2 "-h"
#define OPTION_3 "-o"
#define OPTION_4 "-v"

#define ALGORITHM_1 "md5"
#define ALGORITHM_2 "sha1"
#define ALGORITHM_3 "sha256"

struct Flags;
typedef struct Flags Flags;

void setFlags(int argc, char const *argv[], struct Flags *flag);

void showFlags(Flags flag);

void initFlags(struct Flags *flag);

char* returnCmdOutput(char* cmd);

_Bool checkIfFileNameisValid(const char * filename);

void store_data(const char *filepath, char *data);

void hashOptionFlags(char* hashstring, struct Flags *flag);

void File_info(const char* filename);

void iterate_files(char *name);

char * ret_log_process(char* process_name);



#endif 