#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <semaphore.h>
#include <pthread.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#include "servidor.h"
#include "sope.h"
#include "queue.h"

bank_account_t bank_acc_array[MAX_BANK_ACCOUNTS];
int fd_server, fd_user, fd_slog;
sem_t full, empty;

int main(int argc, char const *argv[])
{
	// Verifying the arguments
	if(argc != MAX_ARG){
		printf("Not enough arguments\n");
		return -1;
	}
	if(verifyArgv(argv[BANK_NUM_POS], 1, 0, MAX_BANK_OFFICES)==-1){
		fprintf(stderr, "ID must have proper width\n");
		return -1;
	}   

	if(verifyArgv(argv[PASS_POS], 0, MIN_PASSWORD_LEN, MAX_PASSWORD_LEN)==-1)
	{
		fprintf(stderr, "ID must have proper width\n");
		return -1;
	}
	//Parsing
	int num_threads = atoi(argv[BANK_NUM_POS]);
	char pass[MAX_PASSWORD_LEN];
	strcpy(pass,argv[PASS_POS]);

	if(openSlog(SERVER_LOGFILE) == -1){
		perror("Unable to open slog.txt\n");
		return -1;
	}

	for(int i = 0; i < MAX_BANK_ACCOUNTS; i++){
		bank_acc_array[i].active = 0;
	}


	//sem_t full, empty;
	pthread_t thread_ar[num_threads];

	//Iniciar os semáforos
	logSyncMechSem(fd_slog, 0, SYNC_OP_SEM_INIT, SYNC_ROLE_PRODUCER, 0, 0);
	sem_init(&full, 0, 0);
	logSyncMechSem(fd_slog, 0, SYNC_OP_SEM_INIT, SYNC_ROLE_PRODUCER, 0, num_threads);
	sem_init(&empty, 0, num_threads);

	//Iniciar as threads = balcôes
	unsigned ids[num_threads];
	for(int i = 0; i < num_threads; i++){
		ids[i]=i+1;
		pthread_create(&thread_ar[i], NULL, processRequest, &(ids[i]));
	}

	// Opening Server Fifo
	if(initServerFiFo()== -1){
		return -1;
	}
	// Admin account created
	createAcc(ADMIN_ACCOUNT_ID, pass, 0);

	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	tlv_request_t req;

	ssize_t reading = 0;

	// Server waiting for a available threads
	while(1){
		reading = read(fd_server, &req, sizeof(tlv_request_t));
        if (reading < 0)
        {
            if (errno != EAGAIN)
                perror("Cannot read");
        }

        else if (reading > 0){
            if (logRequest(fd_slog, getpid(), &req) < 0)
                fprintf(stderr, "main: logRequest failed\n");
			
			int semValue;
			sem_getvalue(&empty, &semValue);
            logSyncMechSem(fd_slog, MAIN_THREAD_ID, SYNC_OP_SEM_WAIT, SYNC_ROLE_PRODUCER, req.value.header.pid, semValue);
            sem_wait(&empty);
            pthread_mutex_lock(&mutex);
            logSyncMech(fd_slog, MAIN_THREAD_ID, SYNC_OP_MUTEX_LOCK, SYNC_ROLE_PRODUCER, req.value.header.pid);
            insertRequest(req);
            pthread_mutex_unlock(&mutex);
            logSyncMech(fd_slog, MAIN_THREAD_ID, SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_PRODUCER, req.value.header.pid);
            sem_post(&full);
            sem_getvalue(&full, &semValue);
            logSyncMechSem(fd_slog, MAIN_THREAD_ID, SYNC_OP_SEM_POST, SYNC_ROLE_PRODUCER, req.value.header.pid, semValue);
			
			if(req.type == OP_SHUTDOWN && req.value.header.account_id == ADMIN_ACCOUNT_ID){
				break;
			}
        }
		
		else
    	{
        	//fprintf(stderr, "EOF!\n");
        }

	}



	//Closing Server Fifo and Slog text file
	closeServerfifo();

	closeSlog();



	return 0;
}

int initServerFiFo(){

	if(mkfifo(SERVER_FIFO_PATH, 0660) != 0) {
		perror("Failed to create server fifo");
		return -1;
 	}

	if( (fd_server = open(SERVER_FIFO_PATH, O_RDONLY | O_NONBLOCK)) == -1)
	{
		perror("Cannot open server fifo.\n");
		return -1;
	}

	return 0;
}

int closeServerfifo(){

 if (remove(SERVER_FIFO_PATH) != 0) {
	fprintf(stderr, "Error: failed to remove fifo.\n");
	return -1;
 }

 return 0;
}

int openSlog(char* filename){

	if((fd_slog = open(filename, O_WRONLY | O_APPEND | O_CREAT)) == -1){
		return -1;
	}
	char* open_separator = "-----------------------OPEN SERVER-------------------------\n";

	write(fd_slog, open_separator, strlen(open_separator));
	return 0;
}

void closeSlog(){

	char* close_separator = "-----------------------CLOSE SERVER-------------------------\n";
	write(fd_slog, close_separator, strlen(close_separator));
	
	close(fd_slog);

	return;
}

void createSalt(char* salt){
	char all_char[17] ="0123456789ABCDEF";
	char tempo[100];
	sprintf(tempo, "%lx", time(NULL));
	int rest = SALT_LEN - strlen(tempo);
	char aux[100] = "";
	for(int i = 0; i < rest; i++){
		aux[i] = all_char[rand()%16];
	}
	sprintf(salt, "%s%s", tempo, aux);
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

void makeFifoPath(int pid, char* userFifo){
    char temp[6];
    snprintf(temp,6,"%05d",pid);
    strcpy(userFifo,USER_FIFO_PATH_PREFIX);
    strcat(userFifo,temp);
}

void * processRequest(void * id){

	unsigned i = *(unsigned*)id;
	logBankOfficeOpen(fd_slog, i, pthread_self());
	int semValue;
	pthread_mutex_t mutex;
	tlv_request_t req;
	char userFifo [USER_FIFO_PATH_LEN];
	//Processing Request -> threads waiting for requests
	while(1){
		sem_getvalue(&full, &semValue);
		logSyncMechSem(fd_slog, i, SYNC_OP_SEM_WAIT, SYNC_ROLE_CONSUMER, 0, semValue);
		sem_wait(&full);
        logSyncMech(fd_slog, i, SYNC_OP_MUTEX_LOCK, SYNC_ROLE_CONSUMER, 0);
		pthread_mutex_lock(&mutex);
		popRequest(&req);
        pthread_mutex_unlock(&mutex);
        logSyncMech(fd_slog, i, SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_CONSUMER, req.value.header.pid);
		sem_post(&empty);
		sem_getvalue(&empty, &semValue);
		logSyncMechSem(fd_slog, i, SYNC_OP_SEM_POST, SYNC_ROLE_CONSUMER, req.value.header.pid, semValue);

		usleep(req.value.header.op_delay_ms * 1000);
		logSyncDelay(fd_slog, i, req.value.header.account_id, req.value.header.op_delay_ms);

		

		tlv_reply_t rep;
		rep.type = req.type;
		rep.value.header.account_id = req.value.header.account_id;
		rep.length = sizeof(rep.value.header);
		rep.value.header.ret_code = RC_OK;

		if (logRequest(fd_slog, i, &req) < 0)
            fprintf(stderr, "main: logRequest failed\n");

		//Abrir o FIFO
		makeFifoPath(req.value.header.pid, userFifo);

		if((fd_user = open(userFifo, O_WRONLY | O_NONBLOCK)) == -1){
			perror("FIFO_user");
			rep.value.header.ret_code = RC_USR_DOWN;
			rep.value.balance.balance = 0;
			logReply(fd_slog, i, &rep);
		}
		else{
			// validar request 
			//LOGIN

			logSyncMech(fd_slog, i, SYNC_OP_MUTEX_LOCK, SYNC_ROLE_ACCOUNT, req.value.header.pid);
			pthread_mutex_lock(&mutex);
			
			if(bank_acc_array[req.value.header.account_id].active == 0){
				//Id not yet created
				rep.value.header.ret_code = RC_ID_NOT_FOUND;
			}
			else{
				char hash[HASH_LEN+1];
				get_Hash(bank_acc_array[req.value.header.account_id].salt, req.value.header.password, hash);
				if(strcmp(hash, bank_acc_array[req.value.header.account_id].hash) != 0){
					//REPLY LOGIN FAIL
					rep.value.header.ret_code = RC_LOGIN_FAIL;
				}
				else if(rep.type == OP_BALANCE){
					if(req.value.header.account_id == ADMIN_ACCOUNT_ID){
						rep.value.header.ret_code = RC_OP_NALLOW;
					}
					else{
						rep.value.balance.balance = bank_acc_array[req.value.header.account_id].balance;
					}
				}
				else if(rep.type == OP_CREATE_ACCOUNT){
					if(bank_acc_array[req.value.create.account_id].active != 0){
						rep.value.header.ret_code = RC_ID_IN_USE;
					}
					else{
						createAcc(req.value.create.account_id, req.value.create.password, req.value.create.balance);
						rep.value.header.ret_code = RC_OK;
					}
				}
				else if(rep.type == OP_TRANSFER){
					if(req.value.header.account_id == ADMIN_ACCOUNT_ID){
						rep.value.header.ret_code = RC_OP_NALLOW;
					}
					else if (bank_acc_array[req.value.transfer.account_id].active == 0) {
						rep.value.header.ret_code = RC_ID_NOT_FOUND;
					}
					else if(req.value.header.account_id == req.value.transfer.account_id){
						rep.value.header.ret_code = RC_SAME_ID;
					}
					else if(bank_acc_array[req.value.header.account_id].balance < req.value.transfer.amount){
						rep.value.header.ret_code = RC_NO_FUNDS;
					}
					else if((bank_acc_array[req.value.transfer.account_id].balance + req.value.transfer.amount) > MAX_BALANCE){
						rep.value.header.ret_code = RC_TOO_HIGH;
					}
					else{
						bank_acc_array[req.value.transfer.account_id].balance += req.value.transfer.amount;
						bank_acc_array[req.value.header.account_id].balance -= req.value.transfer.amount;
						rep.value.transfer.balance = bank_acc_array[req.value.header.account_id].balance;
						rep.value.header.ret_code = RC_OK;
					}
				}
				else if(rep.type == OP_SHUTDOWN){

					if (req.value.header.account_id == ADMIN_ACCOUNT_ID) {

						int active_threads = 0;
						sem_getvalue(&full, &active_threads);
						rep.value.shutdown.active_offices = active_threads;
					}
					else {

						rep.value.header.ret_code = RC_OP_NALLOW;
					}
				}
			}
		}

		pthread_mutex_unlock(&mutex);
        logSyncMech(fd_slog, i, SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_ACCOUNT, req.value.header.pid);

		logReply(fd_slog, i, &rep);

		// enviar reply -> user fifo*
		write(fd_user, &rep, sizeof(tlv_reply_t));

		// close fifo
		close(fd_user);
		}
	pthread_exit(0);
}

void get_Hash(const char* salt, const char* pass, char* hash){
	FILE* f;

	char cmd[200] = "";
	strcat(cmd, "echo -n ");
	strcat(cmd, pass);
	strcat(cmd, salt);
	strcat(cmd, " | sha256sum");

	f = popen(cmd, "r");
	fgets(hash, HASH_LEN+1, f);

	pclose(f);

	
}

void createAcc(uint32_t id, const char* password, uint32_t balance){

	char salt[SALT_LEN+1];
	createSalt(salt);
	char hash[HASH_LEN+1];
	get_Hash(salt, password, hash);


	bank_acc_array[id].account_id = id;
	strcpy(bank_acc_array[id].salt, salt);
	strcpy(bank_acc_array[id].hash, hash);
	bank_acc_array[id].balance = balance;
	bank_acc_array[id].active = 1;


	logAccountCreation(fd_slog, id, &(bank_acc_array[id]));
}