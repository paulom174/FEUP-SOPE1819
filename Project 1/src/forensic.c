#include <stdio.h>
#include <stdlib.h>
#include "forensic.h"
#include "file.h"
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h> 
#include <sys/time.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>

struct Flags f;
struct timeval tv;
char c_time_string[256];
char logfilename[256];
int file_counter = 0;
int dir_counter = 0;

//bool -> options of the user
//char -> saved names of useful files
struct Flags
{
    bool is_directory;
    bool read_files;
    bool calc_hash;
    bool md5;
    bool sha1;
    bool sha256;
    bool store_data;
    char output_txt[50];
    bool generate_file;
    char file_n[50];
    bool error_flag;
};

//interrupt handler for the specified signals
//sig -> type of signal
void siguser_inthandler(int sig){
  switch (sig)
  {
    case SIGUSR1:
    
      file_counter++;
      break;

     case SIGUSR2:

      dir_counter++;
      break;

     case SIGINT:

      printf("Process interrupted\n");
      if (f.generate_file) {
        char * log_reg = ret_log_process("Interrupted by Ctrl-C");
        store_data(logfilename,log_reg);
      }
      
      exit(0);
      break;    
  
    default:
      break;
  }
}

//return current time with milliseconds
void get_time_string(){
 time_t nowtime;
 struct tm *nowtm;
 char tmbuf[64],buf[64];

 gettimeofday(&tv,NULL);

 nowtime = tv.tv_sec;
 nowtm = localtime(&nowtime);
 strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
 snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, tv.tv_usec);
 strcpy(c_time_string,buf);
}

//creates a string in the format <TIME - PID - CURRENT ACTION>
char * ret_log_process(char* process_name){
  char *buffer;
  buffer = malloc(sizeof(char)*256);
  get_time_string();
  strcpy(buffer,c_time_string);
  strcat(buffer," - ");
  char pid[10];
  snprintf(pid, 10,"%d",(int)getpid());
  strcat(buffer,pid);
  strcat(buffer," - ");
  strcat(buffer,process_name);

  return buffer;
}




//debug function not used in fuction
//compares 2 structs of Flag
_Bool compareFlags(Flags *f1, Flags *f2){
  if (f1->read_files == f2->read_files && f1->calc_hash == f2->calc_hash && f1->store_data == f2->store_data &&  f1->md5 == f2->md5 &&  f1->sha1 == f2->sha1 && f1->sha256 == f2->sha256 &&  f1->generate_file == f2->generate_file && strcmp(f1->file_n,f2->file_n) == 0 && strcmp(f1->output_txt,f1->output_txt) == 0) {
    return true;
  }
  else
  {
    return false;
  }
  
  
}


int main(int argc, const char* argv[])
{ 
    signal(SIGUSR1,siguser_inthandler);
    signal(SIGUSR2,siguser_inthandler);
    signal(SIGINT,siguser_inthandler);

    initFlags(&f);
    setFlags(argc,argv,&f);
    if (f.error_flag == true) {
      exit(-1);
    }
    else
    {
      printf("file name :%s\n",f.file_n);
      DIR *dir;
      struct dirent *ent;
      // for just one file it doesn't work
      if ((dir = opendir(f.file_n)) != NULL){

        ent = readdir(dir);

        if (ent->d_type == DT_REG) {

          if(f.generate_file) {
            char command[256];
            strcpy(command,"Analysing File ");
            strcat(command,f.file_n);
            char * log_reg = ret_log_process(command);
            store_data(logfilename,log_reg);
          }

          File_info(f.file_n);
        }
        else
        {
          if(f.generate_file){

            const char *s = getenv("LOGFILENAME");

            if (s == NULL) {
              printf("Error getting Log file name\n");
              return 0;
            }
            else
              {
              strcpy(logfilename,s);
            }
          }
          iterate_files(f.file_n);
        }
      }
      
    }
    

    return 0;
}

//initializes Flags of the struct as well as the strings of important file names
void initFlags(struct Flags *flag){
    flag->is_directory = false;
    flag->read_files = false;
    flag->calc_hash = false;
    flag->md5 = false;
    flag->sha1 = false;
    flag->sha256 = false;
    flag->store_data = false;
    strcpy(flag->output_txt,"");
    flag->generate_file = false;
    strcpy(flag->file_n, "");
    f.error_flag = false;
}

// Goes through all the variables passed in the console and
// activates its corresponding flags 
void setFlags(int argc, char const *argv[], struct Flags *flag){

    char hashstring[50];
    // gets the name of the file/directory to be analised
    // if name is not valid the program exits 
    if (checkIfFileNameisValid(argv[argc - 1]) == false) {
      printf("File name not valid\n");
      f.error_flag = true;
      return;
    }
    else
    {
      strcpy(flag->file_n,argv[argc - 1]);
    }
    
    

  // goes through the remaining variables
  for(int i = 1; i < argc -1; i++)
  {
      //flag 1 activated -> Analyse file
      if (strcmp(OPTION_1,argv[i]) == 0) {
        flag->read_files = true; 
      }

      //flag 2 activated -> Calculate file hashes
      if (strcmp(OPTION_2,argv[i])== 0) {
        flag->calc_hash = true;
        strcpy(hashstring, argv[i+1]);
        //check what hash options have been activated
        hashOptionFlags(hashstring, flag);

      
        //if doesn't find any activates all
        if (flag->sha1 == false && flag->sha256 == false && flag->md5 == false) {
           flag->md5 = true;
           flag->sha1 = true;
           flag->sha256 = true;
        }
        
      }
      //flag 3 activated -> Put analysis and hash sums in a file
      if (strcmp(OPTION_3,argv[i])== 0) {
          flag->store_data = true;
          
          //check if the name of the output file exists
          if (strcmp(argv[i + 1],OPTION_4) != 0 && strcmp(argv[i + 1],flag->file_n) != 0) {
            strcpy(flag->output_txt,argv[i + 1]);
          }
          else
          {
            flag->error_flag = true;
            return;
          }
          
            
      }
      // flag 4 activated -> generate log file
      if (strcmp(OPTION_4,argv[i])== 0) {
        flag->generate_file = true;
      }

      
  }  
}

void hashOptionFlags(char* hashstring, struct Flags *flag){
      //md5 flag activated
    if(strstr(hashstring, ALGORITHM_1)!=NULL){
      flag->md5 = true;
    }
      //sha1 flag activated
    if(strstr(hashstring, ALGORITHM_2)!=NULL){
      flag->sha1 = true;
    }
      //sha256 flag activated
    if(strstr(hashstring, ALGORITHM_3)!=NULL){
      flag->sha256 = true;
    }

    return;
}

//debug function not used in project
//prints all flags and file names
void showFlags(Flags flag){
    printf("Read files: %d\n",flag.read_files);
    printf("Calculate Hash: %d\n",flag.calc_hash);
    printf("Md5: %d\n",flag.md5);
    printf("Sha1: %d\n",flag.sha1);
    printf("Sha256: %d\n",flag.sha256);
    printf("Store data: %d\n",flag.store_data);
    if (flag.store_data == 1) {
        printf("Read files: %s\n",flag.output_txt);
    }
    printf("Generate file: %d\n",flag.generate_file);
    printf("File Path: %s\n",flag.file_n);
}

//return the output of a command of another process
char* returnCmdOutput(char* cmd){
    
    FILE *fp;
    char* buffer = malloc(sizeof(char)*200);

    //uses popen to execute and read the output of the command
    fp = popen(cmd, "r");
    if (fp == NULL){
        printf("Error");
        exit(-1);
    }

    while (fgets(buffer, 200, fp) != NULL){
    }
    
    pclose(fp);
    return buffer;
}

//checks if file name is valid
_Bool checkIfFileNameisValid(const char *filename){
  if (strcmp(filename,OPTION_1) == 0) {
    return false;
  }
  else if(strcmp(filename,OPTION_2) == 0){
    return false;
  }
  else if(strcmp(filename,OPTION_3) == 0){
    return false;
  }
  else if(strcmp(filename,OPTION_4) == 0){
    return false;
  }
  else if(strcmp(filename,ALGORITHM_1) == 0){
    return false;
  }
  else if(strcmp(filename,ALGORITHM_2) == 0){
    return false;
  }
  else if(strcmp(filename,ALGORITHM_3) == 0){
    return false;
  }
  else
  {
    return true;
  }
  
}

//stores a string in a file
void store_data(const char *filepath, char *data)
{
    FILE *fp = fopen(filepath, "a");
    if (fp != NULL)
    {
      
      //printf("Line to be written :%s\n",data);
      fputs(data,fp);
      fputs("\n",fp);
      fclose(fp);
    }
}


void File_info(const char* filename){

  struct stat s;
  char file_type[50];
  char cmd[100] = "file ";
  char buffer[1000];
  char string[1000] = "";
  int pos = 0, flag = 0;

  strcat(string, filename);
  if(f.read_files){
    strcpy(buffer,returnCmdOutput(strcat(cmd, filename)));

    for(unsigned int i = 0; i <= strlen(buffer); i++){
     if(buffer[i] == ' '){
       flag = 1;
     }
     if(buffer[i] == ','){
       break;
      }
      if(flag){
       file_type[pos] = buffer[i];
       pos++;
      }
   }

    char str[50];
    char str1[100];
   strcat(string, ",");
   strcat(string, file_type);
   strcat(string, ",");
   stat(filename, &s);
   sprintf(str, "%ld", s.st_size);
   strcat(string, str);
   strcat(string, ",");
   if((S_ISDIR(s.st_mode))){
    strcat(string, "d");
   }
   else{
     strcat(string, "-");
   }
   if(s.st_mode & S_IRUSR){
     strcat(string, "r");

   }
   else{
     strcat(string, "-");
   }
   if(s.st_mode & S_IWUSR){
     strcat(string, "w");
   }
   else{
     strcat(string, "-");
   }
   if(s.st_mode & S_IXUSR){
     strcat(string, "x");
   }
   else{
     strcat(string, "-");
   }
   if(s.st_mode & S_IRGRP){
     strcat(string, "r");
   }
   else{
     strcat(string, "-");
   }
   if(s.st_mode & S_IWUSR){
     strcat(string, "w");
   }
   else{
     strcat(string, "-");
   }
   if(s.st_mode & S_IXUSR){
     strcat(string, "x");
   }
   else{
     strcat(string, "-");
   }
   if(s.st_mode & S_IROTH){
     strcat(string, "r");
   }
   else{
     strcat(string, "-");
   }
   if(s.st_mode & S_IWOTH){
     strcat(string, "w");
   }
   else{
     strcat(string, "-");
   }
   if(s.st_mode & S_IXOTH){
     strcat(string, "x");
   }
   else{
     strcat(string, "-");
   }
  strcat(string, ",");
  struct tm *t;
  t = localtime(&s.st_mtime);
  strftime(str1, 100, "%Y-%m-%dT%H:%M:%S", t);
  strcat(string, str1);
  strcat(string, ",");
  }

  if(f.md5){
    char md5[100];
    strcpy(cmd, "md5sum ");
    strcpy(buffer,returnCmdOutput(strcat(cmd, filename)));
    pos = 0;
    for(unsigned int i = 0; i <= strlen(buffer); i++){
      if(buffer[i] == ' '){
        pos = i-1;
        break;
      }
    }

    memcpy(md5, buffer, pos*sizeof(char));
    strcat(string, md5);
    if(f.sha1 || f.sha256)
      strcat(string, ",");
  }

  if(f.sha1){
    char sha1[100];
    strcpy(cmd, "sha1sum ");
    strcpy(buffer,returnCmdOutput(strcat(cmd, filename)));
    pos = 0;
    for(unsigned int i = 0; i <= strlen(buffer); i++){
      if(buffer[i] == ' '){
        pos = i-1;
        break;
      }
    }

    memcpy(sha1, buffer, pos*sizeof(char));
    strcat(string, sha1);
    if(f.sha256)
      strcat(string, ",");
  }

  if(f.sha256){
    char sha256[100];
    strcpy(cmd, "sha256sum ");
    strcpy(buffer,returnCmdOutput(strcat(cmd, filename)));
    pos = 0;
    for(unsigned int i = 0; i <= strlen(buffer); i++){
      if(buffer[i] == ' '){
        pos = i-1;
        break;
      }
    }

    memcpy(sha256, buffer, pos*sizeof(char));
    strcat(string, sha256);
  }
  if (f.store_data) {
    store_data(f.output_txt,string);
  }
  else
  {
    printf("%s\n", string);
  }
}


void iterate_files(char *name){
  pid_t pid = fork();

  if (pid == 0) { //son 
    DIR *dir;
    struct dirent *ent;
    
    if ((dir = opendir(name)) != NULL) { 
      
      while((ent = readdir(dir)) != NULL){ 
        
        //if file name is . or .. skip
        if (strcmp(ent->d_name,".") == 0 || strcmp(ent->d_name,"..") == 0) {
          continue;
        }

        //if not regular file or directory skip
        if (ent->d_type != DT_DIR && ent->d_type != DT_REG) {
          continue;
        }

        //if director
        if (ent->d_type == DT_DIR) {
          
          char newName[256];
          strcpy(newName,name);
          strcat(newName,"/");
          strcat(newName,ent->d_name);
          //generate action to put in the log
          if(f.generate_file) {
            char command[256];
            strcpy(command,"Analysing Directory ");
            strcat(command,newName);
            char * log_reg = ret_log_process(command);
            store_data(logfilename,log_reg);
          }
          //sends SIGUSR2 signal
          kill(getpid(),SIGUSR2);
          //calls the function for the current directory
          iterate_files(newName);
        }
        //if file
        if (ent->d_type == DT_REG) {
          
          char FileName[256];
          strcpy(FileName,name);
          strcat(FileName,"/");
          strcat(FileName,ent->d_name);
          
          //generate action to put in the log
          if(f.generate_file) {
            char command[256];
            strcpy(command,"Analysing File ");
            strcat(command,FileName);
            char * log_reg = ret_log_process(command);
            store_data(logfilename,log_reg);
          }
          //sends SIGUSR2 signal
          kill(getpid(),SIGUSR1);
          //analises the file
          File_info(FileName);
        } 
      }
      
    }
    else {
      /* could not open directory */
      if(f.generate_file) {
        
        char * log_reg = ret_log_process("Error could not open directory");
        store_data(logfilename,log_reg);
      }
      perror ("error");
      return;
    }
    exit(0);
  }
  else if(pid < 0)
  {
    /* code */
  }
  else // dad
  {
    wait(NULL);
  }
}
