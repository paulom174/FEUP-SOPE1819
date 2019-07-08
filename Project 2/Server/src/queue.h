#include "sope.h"

#define MAX_REQUEST 50

tlv_request_t peek();

bool isEmpty();

bool isFull();

int size();

void insertRequest(tlv_request_t data);

void popRequest(tlv_request_t* data);