#include<iostream>
#include<iomanip>
#include<fstream>
#include<vector>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <sstream>
#include <signal.h>

using namespace std;

struct my_msgbuf {
    long mtype;
    char mtext[200];
};

int msqid;

void printBoard(vector< vector<string> > board,int upid){
	std::cout<<"Player "<<upid<<" board:"<<std::endl;
	for(int i=0;i<board.size();++i){
		vector<string> red = board[i];
		for(int j=0;j<red.size();++j){
			std::cout<<std::setw(2)<<red[j];
		}
		std::cout<<std::endl;
		std::cout<<std::endl;
	}
}

vector< vector<string> > generateBoard(int board_size, int ship_number,int upid){
int fields = board_size*board_size;
double prob = static_cast<double>(ship_number)/fields;
int currentShipNumber=0;
srand(upid);
vector< vector<string> > board;

for(int r=0;r<board_size;++r){
	vector<string> red;
	for(int i=0;i<board_size;++i){
		red.push_back("-");
		
	}
	board.push_back(red);	
	}

int x;
int y;
while(currentShipNumber<ship_number){
	x=rand()%(board_size);
	y=rand()%(board_size);
	if (board[x][y]=="-"){
		board[x][y]="o";
		currentShipNumber++;
	}
}

return board;
}


vector< vector<string> > generateEmptyBoard(int board_size){
	
	vector< vector<string> > board;
	for(int r=0;r<board_size;++r)
	{
		vector<string> red;
		for(int i=0;i<board_size;++i)
		{
			red.push_back("-");
		}
		board.push_back(red);	
	}
	return board;
}

void retreat(int failure) 
{
    if (msgctl(msqid, IPC_RMID, NULL) == -1) {
        perror("msgctl");
        exit(1);
    }
    exit(0);
}


//int main(int argc, char* argv[]){
int main(){
	/*cout<<argv[0]<<argv[1]<<argv[2]<<endl;
	istringstream ss0(argv[1]);
	istringstream ss1(argv[2]);
	istringstream ss2(argv[3]);
	int board_size;
	int ship_number;	
	int upid;
	if (!(ss0 >> board_size))
    		cerr << "Invalid number " << argv[0] << '\n';
	if (!(ss1 >> ship_number))
    		cerr << "Invalid number " << argv[1] << '\n';
	if (!(ss2 >> upid))
    		cerr << "Invalid number " << argv[2] << '\n';
	*/
	int board_size=4;
	int ship_number=6;	
	int upid=getpid();

	int hitnumber=0;
	int x,y;
	vector< vector<string> > hitboard;
	vector< vector<string> > board;

	struct my_msgbuf buf;
	key_t key;
	char text[]="Ready";

	
	char * pch; //message split inco coords

	key = getuid();
	key = 112;
	cout<<"KEY: "<<key<<endl;
	board=generateBoard(board_size,ship_number,upid);
	hitboard=generateEmptyBoard(board_size);
	printBoard(board,upid);

	printBoard(hitboard,upid);


	memcpy(buf.mtext, text, strlen(text)+1);
    	buf.mtype = 1;

	if ((msqid = msgget(key, 0600 | IPC_CREAT)) == -1) { /* connect to the queue */
		perror("msgget");
		exit(1);
    	}
	else{
		cout<<"I'm connected"<<endl;	
	}


	//Send message saying that you are ready
   	if (msgsnd(msqid, (struct msgbuf *)&buf, strlen(text)+1, 0) == -1)
        	perror("msgsnd");
	else{
		//cout<<"I am ready"<<endl;
	}
	
	sigset(SIGINT, retreat);

	int milliseconds=upid;
	usleep(milliseconds);
	
	for(;;) { /* Wait for message "Ready." */
		if (msgrcv(msqid, (struct msgbuf *)&buf, sizeof(buf)-sizeof(long), 0, 0) == -1) {
			perror("msgrcv");
			exit(1);
		}
		else{
			//cout<<buf.mtext<<endl;
			if(!strcmp(buf.mtext,"Ready")){
				cout<<buf.mtext<<endl;
				break;
			}
		}
    	}
	string output;
	int xi,yi;
	while(true){

		//Recieve Coords
		for(;;) { // Wait for message "Ready." 
			if (msgrcv(msqid, (struct msgbuf *)&buf, sizeof(buf)-sizeof(long), 0, 0) == -1) {
				perror("msgrcv");
				exit(1);
			}
			else{
				if(!strcmp(buf.mtext,"Ready")){
					output="Ready";
					memcpy(buf.mtext, output.c_str(), strlen(text)+1);
			    		buf.mtype = 1;
					if (msgsnd(msqid, (struct msgbuf *)&buf, strlen(text)+1, 0) == -1)
						perror("msgsnd");
				}
				else{
				cout<<"Pucano na: "<<buf.mtext<<endl;
				break;
				}
			}
		}
		
		//Evaluate hit miss
		
		pch = strtok (buf.mtext," ,.-");
		cout<<"Koordinate: "<<pch[0]<<" "<<pch[2]<<endl;
		
		
		xi = pch[0]-'0';
		yi = pch[2]-'0';
		cout<<board[xi][yi]<<endl;
	
		if("o"==board[xi][yi]){
			//cout<<"It is a hit!"<<endl;
			hitnumber++;
			output="Pogodak!";			
			
		}
		else{
			//cout<<"It is a miss!"<<endl;
			output="Promasaj";
		}


		//Send hit/miss
		memcpy(buf.mtext, output.c_str(), 20);
    		buf.mtype = 1;
		if (msgsnd(msqid, (struct msgbuf *)&buf, 20, 0) == -1)
        		perror("msgsnd");
		else{
			cout<<"Message sent!"<<endl;
		}

		if(hitnumber>=ship_number){
			cout<<"Poraz";
			output="Pobjeda";
			memcpy(buf.mtext, output.c_str(), strlen(text)+1);
	    		buf.mtype = 1;
			if (msgsnd(msqid, (struct msgbuf *)&buf, strlen(text)+1, 0) == -1)
				perror("msgsnd");
			break;
		}		
	

		//printBoard(hitboard,upid);
		cout<<"Upisi x i y koordinate tocke koju zelis gadjati :";
		cin>>x>>y;
		//cout<<"X: "<<x<<" Y: "<<y<<endl;
		cout<<"Ispali na polje: "<<x<<" "<<y<<endl;
		output = to_string(x)+" "+to_string(y);
		hitboard[x][y]="x";
	
		//Send Coords
		memcpy(buf.mtext, output.c_str(), strlen(text)+1);
    		buf.mtype = 1;
		if (msgsnd(msqid, (struct msgbuf *)&buf, strlen(text)+1, 0) == -1)
        		perror("msgsnd");


		//Wait Reply
		for(;;) { // Wait for message "Ready." 
			if (msgrcv(msqid, (struct msgbuf *)&buf, sizeof(buf)-sizeof(long), 0, 0) == -1) {
				perror("msgrcv");
				exit(1);
			}
			else{
				cout<<buf.mtext<<endl;
				break;
			}
		}
		
		
	
	}
	/*
	int fields = board_size*board_size;
	double prob = static_cast<double>(ship_number)/fields;
	int currentShipNumber=0;
	srand(upid);
	for(int r=0;r<board_size;++r){
		vector<string> red;
		for(int i=0;i<board_size;++i){
			red.push_back("-");
		
		}
		board.push_back(red);	
		}

	int x;
	int y;
	while(currentShipNumber<ship_number){
		x=rand()%(board_size);
		y=rand()%(board_size);
		if (board[x][y]=="-"){
			board[x][y]="o";
			currentShipNumber++;
		}
	}


	std::cout<<"Player "<<upid<<" board:"<<std::endl;
	for(int i=0;i<board.size();++i){
		vector<string> red = board[i];
		for(int j=0;j<red.size();++j){
			std::cout<<std::setw(2)<<red[j];
		}
		std::cout<<std::endl;
		std::cout<<std::endl;
	}
	*/
	char z;
	cin>>z;
	return 0;
}
