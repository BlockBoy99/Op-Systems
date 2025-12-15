#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<fcntl.h>  // for the open() function
#include<unistd.h> // for read(), write() and close() functions

#define BUFSIZE 10




int main(){

    int fd1=open("./textfile1.txt",O_RDONLY);  // opens the file in read only mode and returns a file descriptor for the file
    int fd2=open("./textfile2.txt",O_WRONLY);  // opens the file in read only mode and returns a file descriptor for the file

    int x;

    if(fd1 < 0||fd2<0){
        write(2,"Error opening file\n",sizeof("Error opening file\n")); // writes the error message to stderr
        exit(1);
    }

    char str[BUFSIZE];

    printf("Starting Writing");
    while((x=read(fd1,str,BUFSIZE-1)) > 0){ // read() reads up to BUFSIZE-1 bytes from fd1 and stores in str
                                           // the number of bytes actually read is returned
            str[x]='\0';
            write(fd2,str,strlen(str));   // '1' is the file dscriptor for stdout, hence this is equivalent to printf("%s", str)
    }
    close(fd1);
    close(fd2);
    return 0;
}
