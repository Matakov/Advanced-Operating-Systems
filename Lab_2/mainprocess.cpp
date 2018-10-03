#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
      
#include <stdlib.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <time.h>
#include <string>
#include <sys/wait.h>
         
using namespace std;

#define MAXREAD 20 /* najveca duljina poruke*/
#define NUMPROC 3 //Broj procesa
#define REQUEST 0
#define REPLY 1

int main(void)
{
	int clk[NUMPROC];
	char buf[MAXREAD] = "";
	char message[] = "Kroz cijev!";
	char ti[256];

	for(int i=0;i<NUMPROC;++i){
		sprintf(ti, "%d", i);
		unlink(ti);
		if (mknod(ti, S_IFIFO | 00600, 0)==-1)
			exit(1);
	}

	int mainpid=getpid();
	cout<<"Main pid: "<<mainpid<<endl;
	int pids[NUMPROC];
	int num;
	int num_reply=NUMPROC-1;
	int tty;
	for(int i=0;i<NUMPROC;++i){
		//std::cout<<i<<std::endl;
		if(getpid()==mainpid){
			tty = fork();
			switch (tty) {
				case -1: // dijete nije kreirano
					exit(1);

				case 0:// dijete je kreirano i spojeno na sve cijevi
					//pids[i] = getpid();
					//cout<<"PID: "<<pids[i]<<endl;
					//cout<<num<<endl;
					
					//Dretva(i);
					//execl(progname, progname, argument1, argument2, (char *)NULL);
					execl("/usr/bin/xterm", "xterm", "-e", "./dretva", to_string(i).c_str() , (char*)NULL);
					break;
				default:
					pids[i] = tty;
					break;	
			}
		}		
	}
	
	/*
	if(getpid()==mainpid){
		for(int l=0;l<NUMPROC;++l){
			while (waitpid(pids[l], NULL, 0) > 0);
		}
	}
	*/
	char k;
	cin>>k;
	return 0;
}

