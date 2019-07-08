#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "types.h"
#include "cliente.h"
#include "constants.h"
#include "errno.h"
#include "time.h"
#include "sope.h"

int fd_server, fd_user, fd_ulog;
char userFifo[USER_FIFO_PATH_LEN];


int main(int argc, char const *argv[])
{
    tlv_request_t req;
    // Opening ulog fil text
	if(openUlog(USER_LOGFILE) == -1){
		perror("Unable to open ulog.txt\n");
		return -1;
	}
    // Verifying the input
    if (argc != 6) {
        printf("Not enough arguments\n");
        return -1;
    }
    if(verifyArgv(argv[ID_POS], 1, 0, WIDTH_ID)==-1){
            fprintf(stderr, "ID must have proper width\n");
            return -1;
    }
    if(verifyArgv(argv[DELAY_POS], 1, 0, MAX_OP_DELAY_MS)==-1){
            fprintf(stderr, "Delay must have proper width\n");
            return -1;
    }
    if(verifyArgv(argv[PASSW_POS], 0, MIN_PASSWORD_LEN, MAX_PASSWORD_LEN) == -1){
            fprintf(stderr, "Password must have the proper length\n");
            return -1;
    }
    if(verifyArgv(argv[OP_POS], 1, 0, WIDTH_OP) == -1){
            fprintf(stderr, "Operation must have the proper limit\n");
            return -1;
    }
    // Creatting request
    if(createRequest(&req, argv, argc)==-1){
       fprintf(stderr, "Invalid Request\n");
       return -1;
    }
    logRequest(fd_ulog, 0, &req);

    // Creatting User fifo and opening
    makeFifoPath(getpid());

    if(initUser_Fifo() == -1){
        return -1;
    }
    if((fd_user = open(userFifo, O_RDONLY | O_NONBLOCK)) == -1){
        perror("FIFO_user");
        return -1;
    }
    
    // Sending request to server FIFO
    if(SendRequest(&req) == -1){
        return -1;
    }
    // Waiting for a reply
    // ...
    // ...
    // ...

    // Reading reply from server FIFO
    readReply(&req);

    // Ending user program -> closing Fifo and Ulog file text
    closeUser_Fifo();

    closeUlog();

    return 0;
}

void fillHeader(req_value_t * t, uint32_t id, char * password, uint32_t delay){

    t->header.account_id = id;
    t->header.pid = getpid();
    t->header.op_delay_ms = delay;
    strcpy(t->header.password, password);
}

int openUlog(char* filename){
    
	if((fd_ulog = open(filename, O_WRONLY | O_APPEND | O_CREAT)) == -1){
		return -1;
	}

	char* open_separator = "-----------------------OPEN USER-------------------------\n";

	write(fd_ulog, open_separator, strlen(open_separator));
	return 0;
}

void  closeUlog(){

    char* close_separator = "-----------------------CLOSE USER-------------------------\n";
	write(fd_ulog, close_separator, strlen(close_separator));
	
	close(fd_ulog);

	return;
}

int verifyArgv(char const* input, int is_unsigned, unsigned low, unsigned high){
    if(is_unsigned){
        unsigned aux = atoi(input);
        
        if(aux < low || aux > high){
            return -1;
        }
        return 0;
    }
    else{
        unsigned len = strlen(input);
        if(len < low || len > high){
            return -1;
        }
        return 0;
    }
}


int createRequest(tlv_request_t* req, char const *argv[], int argc){

    int id = atoi(argv[ID_POS]);
    int delay = atoi(argv[DELAY_POS]);
    char pass[MAX_PASSWORD_LEN];
    strcpy(pass,argv[PASSW_POS]);        
    req_value_t value;
    fillHeader(&value, id,pass,delay);
    req->value = value;
    req->length = sizeof(req_header_t);

    // Examining the Operation requested 
    if (strcmp(argv[4],"1")== 0 || strcmp(argv[4],"3")== 0) {
        // Balance
        if(strcmp(argv[4],"1")== 0){
            req->type =  OP_BALANCE;
        }
        // Shutdown
        if(strcmp(argv[4],"3")== 0){
            req->type =  OP_SHUTDOWN;
        }
        return 0;
    }
    //Create account
    else if (strcmp(argv[4],"0") == 0) {
    
        if (argc < 6)
        {
            return -1;
        }

        req->type =  OP_CREATE_ACCOUNT;
        req->length += sizeof(req_create_account_t);
        req_create_account_t create;
        if(ParseCreateRequest(&create, argv[EXTRA_INFO]) == -1){
            return -1;
        }
        req->value.create = create;
        return 0;
    }
    //Transfer
    else if (strcmp(argv[4],"2") == 0) {
        
        if (argc < 6)
        {
            return -1;
        }
        req->length += sizeof(req_transfer_t);
        req_transfer_t transfer;
        if(ParseTransferRequest(&transfer, argv[EXTRA_INFO]) == -1){
            return -1;
        }
        req->type =  OP_TRANSFER;
        req->value.transfer = transfer;
        return 0;
    }
    else
    {
        fprintf(stderr, "Error in the operation requested\n");
        return -1;
    }
}

void makeFifoPath(int pid){
    char temp[6];
    snprintf(temp,6,"%05d",pid);
    strcpy(userFifo,USER_FIFO_PATH_PREFIX);
    strcat(userFifo,temp);
}

int initUser_Fifo(){
    if(mkfifo(userFifo, 0660) != 0) {
        printf("%s\n", userFifo);
        fprintf(stderr, "Cannot create user fifo.\n");
        return -1;
    }
    return 0;
}

int closeUser_Fifo(){
    if (remove(userFifo) != 0) {
        fprintf(stderr, "Cannot remove user fifo.\n");
        return -1;
    }
    return 0;
}

void readReply(tlv_request_t* req){

    tlv_reply_t rep;

    time_t start = time(NULL);
    time_t cur_time = start;
	ssize_t reading = 0;

    // If the server takes more than FIFO_TIMEOUT_SECS, TIMEOUT reply will be send
	while((cur_time - start) <= FIFO_TIMEOUT_SECS)
    {   
        cur_time = time(NULL);
		reading = read(fd_user, &rep, sizeof(tlv_reply_t));
        if (reading < 0)
        {
            if (errno != EAGAIN)
                perror("Cannot read");
        }
        // If it reads something, it means a reply was received
        else if (reading > 0){
            if (logReply(fd_ulog, getpid(), &rep) < 0)
                fprintf(stderr, "Cannot log\n");
            return;
        }
		
		else
    	{
        	//fprintf(stderr, "Waiting for a reply\n");
        }
	}
    rep.type = req->type;
    rep.value.header.account_id = req->value.header.account_id;
    rep.length = sizeof(rep.value.header);
    rep.value.header.ret_code = RC_SRV_TIMEOUT;
    rep.value.balance.balance = 0;
    logReply(fd_ulog, getpid(), &rep);


}

int ParseTransferRequest(req_transfer_t* transfer, const char * ch){

    const char s[2] = " ";
    char id[WIDTH_ID];
    char amount[WIDTH_BALANCE];
    char temp1[strlen(ch)];
    strcpy(temp1,ch);
    char *temp = strtok(temp1, s); 
    int i = 0;

    while (temp != NULL)
    {
        if (strcmp(temp,"") == 0)
        {
            continue;
        }
        else if (i == 0 && strlen(temp) <= 4)
        {
            i++;
            strcpy(id,temp);
            /*if(strlen(id) != WIDTH_ID){
                fprintf(stderr, "Invalid input\n");
                return -1;
            }*/
        }
        else
        {
            strcpy(amount,temp);
            /*if(verifyArgv(amount, 1, MIN_BALANCE, MAX_BALANCE)==-1){
                fprintf(stderr, "Invalid input\n");
                return -1;
            }*/
        }
        
        temp = strtok(NULL, s);
    }
    
    int idn = atoi(id), amountn = atoi(amount);
    
    transfer->account_id = idn;
    transfer->amount = amountn;


    return 0;

}

int ParseCreateRequest(req_create_account_t* create, const char * ch){
    
    const char s[2] = " ";
    char id[WIDTH_ID];
    char amount[WIDTH_BALANCE];
    char password[MAX_PASSWORD_LEN];
    char temp1[strlen(ch)];
    strcpy(temp1,ch);
    char *temp = strtok(temp1, s); 
    int i = 0;

    while (temp != NULL)
    {
        if (strcmp(temp,"") == 0)
        {
            continue;
        }
        else if (i == 0 && strlen(temp) <= WIDTH_ID)
        {
            i++;
            strcpy(id,temp);
            /*if(strlen(id) != WIDTH_ID){
                fprintf(stderr, "Invalid input\n");
                return -1;
            }*/
        }
        else if (i == 1 && strlen(temp) <= WIDTH_BALANCE)
        {
            i++;
            strcpy(amount,temp);
            /*if(verifyArgv(amount, 1, MIN_BALANCE, MAX_BALANCE)==-1){
                fprintf(stderr, "Invalid input\n");
                return -1;
            }*/
        }
        else
        {
            strcpy(password,temp);
            /*if(verifyArgv(amount, 0, MIN_PASSWORD_LEN, MAX_PASSWORD_LEN)==-1){
                fprintf(stderr, "Invalid input\n");
                return -1;
            }*/
        }
        
        
        temp = strtok(NULL, s);
    }
    
    int idn = atoi(id), amountn = atoi(amount);
    
    create->account_id = idn;
    create->balance = amountn;
    strcpy(create->password,password);


    return 0;
}

int SendRequest(tlv_request_t* req){
    if((fd_server = open(SERVER_FIFO_PATH, O_WRONLY | O_NONBLOCK | O_APPEND)) == -1){
        //Send SHUT_DOWN reply
        //perror("FIFO_server");
        tlv_reply_t rep;
		rep.type = req->type;
		rep.value.header.account_id = req->value.header.account_id;
		rep.length = sizeof(rep.value.header);
		rep.value.header.ret_code = RC_SRV_DOWN;
		rep.value.balance.balance = 0;
		logReply(fd_ulog, getpid(), &rep);
        return -1;
    }

    //char aux[sizeof(tlv_request_t)];
	//memcpy(aux, req, sizeof(tlv_request_t));

    if(write(fd_server, req, sizeof(tlv_request_t))==-1){
        fprintf(stderr, "Cannot write into fd_server");
        return -1;
    }
    printf("%d\n", req->value.header.account_id);
    return 0;
}



