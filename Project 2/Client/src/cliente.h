#ifndef _CLIENT_H_
#define _CLIENT_H_

#include "types.h"

#define ID_POS 1
#define PASSW_POS 2
#define DELAY_POS 3
#define OP_POS 4
#define EXTRA_INFO 5

#define PASSWORD_LENGTH 99

#define READ 0
#define WRITE 1

int createRequest(tlv_request_t* req, char const *argv[],  int argc);

void fillHeader(req_value_t* t,uint32_t id, char *password, uint32_t delay);

int verifyArgv(char const* input, int is_unsigned, unsigned low, unsigned high);

void fillCreateRequest(req_value_t *op, uint32_t id, uint32_t amount, char * password);

void fillTransferRequest(req_value_t *op, uint32_t id, uint32_t amount);

void makeFifoPath(int pid);

void readReply(tlv_request_t* req);

int initUser_Fifo();

int closeUser_Fifo();

int ParseTransferRequest(req_transfer_t * transfer, const char * ch);

int ParseCreateRequest(req_create_account_t * create, const char * ch);

int SendRequest(tlv_request_t* req);

#endif