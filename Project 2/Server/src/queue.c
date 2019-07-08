#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "sope.h"
#include "queue.h"

tlv_request_t RequestArray[MAX_REQUEST];
int front = 0;
int rear = -1;
int itemCount = 0;

tlv_request_t peek() {
   return RequestArray[front];
}

bool isEmpty() {
    if(itemCount == 0)
        return false;
    else
        return true;
}

bool isFull() {
    if(itemCount == MAX_REQUEST)
        return true;
    else
        return false;
}

int size() {
   return itemCount;
}

void insertRequest(tlv_request_t data) {

   if(!isFull()) {
	
      if(rear == MAX_BANK_OFFICES-1) {
         rear = -1;            
      }       

      RequestArray[++rear] = data;
      itemCount++;
   }
}

void popRequest(tlv_request_t* data) {

   memcpy(data, &RequestArray[front++], sizeof(tlv_request_t));
	
   if(front == MAX_REQUEST) {
      front = 0;
   }
	
   itemCount--; 

}

