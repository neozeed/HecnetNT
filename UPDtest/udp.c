/*Simple program to display UDP packets to verify data is being received.*/


#include <stdio.h>
#include <winsock2.h>
#include <windows.h>


#define bzero(d,n) memset(d,0,n)


int main(int argc, char**argv)
{
   int sockfd,n;
   struct sockaddr_in servaddr,cliaddr;
	unsigned int len;
   char mesg[1000];
	int iResult;
	  WSADATA wsaData;

      iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }

   sockfd=socket(AF_INET,SOCK_DGRAM,0);

   bzero(&servaddr,sizeof(servaddr));
   servaddr.sin_family = AF_INET;
   servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
   servaddr.sin_port=htons(5500);
   bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));

   for (;;)
   {
	int j;
	j=0;
      len = sizeof(cliaddr);
      n = recvfrom(sockfd,mesg,1000,0,(struct sockaddr *)&cliaddr,&len);
      //sendto(sockfd,mesg,n,0,(struct sockaddr *)&cliaddr,sizeof(cliaddr));
      printf("-------------------------------------------------------\n");
      mesg[n] = 0;
      printf("Received the following: bytes %d\n",n);
while(j<n)
	{printf("%02x ", mesg[j] & 0xff);
	j++;
	if(j % 22 ==0){printf("\n");}
	}
      printf("\n-------------------------------------------------------\n");
   }
}