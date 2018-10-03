#include<iostream>
#include<iomanip>
#include<fstream>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include <time.h>
#include <string>
#include <sys/wait.h>

struct my_msgbuf {
    long mtype;
    char mtext[200];
};


int main(){

	int msqid;
	key_t key;

	
	key = getuid();
	key = 112;
	std::cout<<"Key: "<<key<<std::endl;
	/*
	int board_size;
	std::cout<<"Upisi velicinu ploce: "<<std::endl;
	std::cin>>board_size;
	
	int ship_number;
	std::cout<<"Upisi kolicinu brodova: "<<std::endl;
	std::cin>>ship_number;
	*/
	//Napravi red	
	if ((msqid = msgget(key, 0600 | IPC_CREAT)) == -1) {
		perror("msgget");
		exit(1);
	}
	
	int mainpid = getpid();
	int child1;
	int child2;
	pid_t pid = fork();
	pid_t pid2;
	if (getpid()!=mainpid){
		child1=getpid();
	}
	if (getpid()==mainpid){
		pid2 = fork();
	}
	if(getpid()!=mainpid && getpid()!=child1){
		child2=getpid();
	}
	int counter = 0;
	int player1;
	int player2;
	//Call player1
	if(getpid()==child1){
		//std::string pin = std::to_string(getpid());
		//std::string input1 = "/home/matko/Documents/FER/NOS/PLAYER "+std::to_string(board_size)+" "+std::to_string(ship_number)+" "+pin;
		//execl("/usr/bin/xterm", "xterm -e", input1.c_str() , NULL);
		execl("/usr/bin/xterm", "xterm -e", "./player", NULL);
		//execl("/usr/bin/xterm", "xterm -e", "", NULL);
		//player1=playerFunc(board_size,ship_number,getpid());
	}
	//Call player2
	if(getpid()==child2){
		std::string pin2 = std::to_string(getpid());
		//std::string input2 ="/home/matko/Documents/FER/NOS/player "+std::to_string(board_size)+" "+std::to_string(ship_number)+" "+pin2;
		//execl("/usr/bin/xterm", "xterm -e", input2.c_str() , NULL);
		execl("/usr/bin/xterm", "xterm -e", "./player2" , NULL);
		//player2=player(board_size,ship_number,getpid());
	}

	while (waitpid(child1, NULL, 0) > 0);
	while (waitpid(child2, NULL, 0) > 0);
	if(msgctl(msqid,IPC_RMID,NULL)){
		std::cout<<"Red poruka je ugasen"<<std::endl;
	}
	return 0;
}
