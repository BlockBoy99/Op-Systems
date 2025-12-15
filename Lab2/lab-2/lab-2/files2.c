#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<fcntl.h>  // for the open() function
#include<unistd.h> // for read(), write() and close() functions

#define BUFSIZE 10

int main(){

    int fd1=open("./textfile1.txt",O_RDONLY);
    int fd2=open("./textfile2.txt",O_WRONLY | O_CREAT, 0600);
    int x;

    if(fd1 < 0 || fd2 < 0){
        write(2,"Error opening file\n",sizeof("Error opening file\n"));
        exit(1);
    }

    char str[BUFSIZE];

    printf("Writing started\n");
    while((x=read(fd1,str,BUFSIZE-1)) > 0){
        
            str[x]='\0';
            write(fd2,str,strlen(str));
    }
    printf("Writing finished\n");
    close(fd1);
    close(fd2);
    return 0;

}