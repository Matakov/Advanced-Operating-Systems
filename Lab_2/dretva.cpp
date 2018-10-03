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
#include <sstream>
#include <queue> 
         
using namespace std;

#define MAXREAD 20 /* najveca duljina poruke*/
#define NUMPROC 3 //Broj procesa
#define REQUEST 0
#define REPLY 1

struct my_msgbuf {
	int type; 	//vrsta poruke
	int i;		//id procesa
  	int clk;	//lokalni sat
};

void KO(){
	int pid=getpid();
	std::cout<<"Broj procesa je: "<<pid<<std::endl;
	for(int i=0;i<5;++i){
		std::cout<<i<<std::endl;
	}
	usleep(1000000);
}

int retMax(int x,int y){
	return (x>y) ? x+1 : y+1;
}

int sendRequest(int pfd[NUMPROC],int clk,int num,queue<my_msgbuf>& my_queue){
	my_msgbuf buf,new_buf;
	buf.type=REQUEST;
	buf.i=num;
	buf.clk=clk;
	int newClock=clk;
	for(int i=0;i<NUMPROC;++i){
		if(num!=i){
			(void) write(pfd[i], &buf, 21);
			cout<<"Proces P"<<num<<" šalje procesu P"<<i<<" poruku "<<buf.clk<<endl;
		}
	}
	int num_reply=NUMPROC-1;
	while(num_reply){
		//cout<<num_reply<<endl;
		(void) read(pfd[num],&buf,21);
		if(buf.clk == clk && REPLY==buf.type && buf.i!=num){
			--num_reply;
			newClock=retMax(newClock,buf.clk);
			//cout<<"Proces P"<<num<<" primio poruku "<<buf.clk<<" od procesa P"<<buf.i<<" broj odgovora potreban "<<num_reply<<endl;
		}
		else if(buf.clk < clk && REQUEST==buf.type && buf.i!=num) {
			newClock=retMax(newClock,buf.clk);
			new_buf.type=REPLY;
			new_buf.i=num;
			new_buf.clk=buf.clk;
			//cout<<"Proces "<<num<<" vraća "<<new_buf.clk<<" procesu "<<buf.i<<endl;
			(void) write(pfd[buf.i], &new_buf, 21);

		}
		else if(buf.clk > clk && REQUEST==buf.type && buf.i!=num){
			//cout<<"P"<<num<<": Nije prioritet, odgovori kasnije."<<endl;
			newClock=retMax(newClock,buf.clk);
			//cout<<buf.type<<" "<<buf.i<<" "<<buf.clk<<endl;
			my_queue.push(buf);
		}
	
	}
	//cout<<"Idem van!"<<endl;

	return newClock;
}


int sendReply(int pfd[NUMPROC],int clk,int num, queue<my_msgbuf>& my_queue){
	my_msgbuf buf,new_buf;
	cout<<"Broj procesa je: "<<num<<endl;
	while(!my_queue.empty()){
		//read(pfd[num], &buf, MAXREAD);
		buf=my_queue.front();
		my_queue.pop();
		cout<<"Proces "<<num<<" je primio poruku "<<buf.clk<<endl; //" od procesa "<<buf.i<<endl;
		clk=retMax(clk,buf.clk);
		cout<<"Novi clock je: "<<clk<<endl;
		//TREBA OVO ZAVRSTITI
		//cout<<static_cast<int>(buf.type)<<" "<<static_cast<int>(REQUEST)<<endl;
		if(buf.type==REQUEST && buf.i!=num){ //ako je pridosli clock manji treba poslati reply
			new_buf.type=REPLY;
			new_buf.i=num;
			new_buf.clk=buf.clk;
			//cout<<"Proces "<<num<<" vraća "<<new_buf.clk<<" procesu "<<new_buf.i<<endl;
			(void) write(pfd[buf.i], &new_buf, 21);
		}
		
	}
	return clk;
}


int main(int argc, char* argv[]){
	queue<my_msgbuf> my_queue;
	cout<<argc<<endl;
	int pfd[NUMPROC];
	stringstream str;
    	str << argv[1];
    	int x;
   	str >> x;
	char ti[256];
	int clk=x;
	int num=x;
	int num_reply=NUMPROC-1;
	//cout<<"PID: "<<getpid()<<"broj"<<br<<endl;
	for(int j=0;j<NUMPROC;++j){
		sprintf(ti, "%d", j);
		//cout<<"Cijev: "<<ti<<endl;
		if(j==num){
			pfd[j] = open(ti, O_RDWR); 
			//cout<<"Cijev "<<j<<" je otvorena za citanje i pisanje na procesu "<<num<<endl;
			//Ako je vlastita cijev, otvoreno je za citanje i pisanje
		}
		else{
			pfd[j] = open(ti, O_WRONLY); //Ako je tudja cijev, otvoreno je za pisanje
			//cout<<"Cijev "<<j<<" je otvorena za pisanje na procesu "<<num<<endl;
		}
	}
	usleep(getpid());
	//Zelim uci u kriticni odsjecak
	//Posalji zahtjev
	
	for(int z=0;z<3;++z){
		clk = sendRequest(pfd,clk,num,my_queue);
		KO();
		clk = sendReply(pfd,clk,num,my_queue);
	}	
	char n;
	cin>>n;
	return 0;
}
