#ifndef _SERVIDOR_H_
#define _SERVIDOR_H_
#include <stdint.h>


int initServerFiFo();

int closeServerfifo();

int openSlog(char* filename);

void closeSlog();

int verifyArgv(char const* input, int is_unsigned, unsigned low, unsigned high);

void * processRequest(void * id);

void createSalt(char* salt);

void get_Hash(const char* salt, const char* pass, char* hash);

void makeFifoPath(int pid, char* userFifo);

void createAcc(uint32_t id, const char* password, uint32_t balance);

#endif