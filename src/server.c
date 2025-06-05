#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include "honeybee.h"

/**
 * Provides TCP server functionality, handles multiple connections by forking.
 *
 * @copyright Copyright (C) 2016 ProfiWeb sro (http://profiweb.biz/).
 * @author Marian Tomlak
 * @license BSD
 */

/**
 * Starts the 
 * 
 * @return [description]
 */
int server_start(int port_num)
{
   int sockfd, newsockfd, clilen;
   char buffer[BUF_SZ];
   struct sockaddr_in serv_addr, cli_addr;
   int n, pid;

   /* First call to socket() function */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0) {
      die_err("Error opening socket");
   }
   
   /* Initialize socket structure */
   bzero((char *) &serv_addr, sizeof(serv_addr));
   
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(port_num);
   
   /* Now bind the host address using bind() call.*/
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      die_err("Error on binding");
   }
   
   /* Now start listening for the clients, here
      * process will go in sleep mode and will wait
      * for the incoming connection
   */
   
   listen(sockfd,5);
   clilen = sizeof(cli_addr);
   
   while (1) {
      newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        
      if (newsockfd < 0) {
         die_err("Error on accept");
      }
      
      /* Create child process */
      pid = fork();
        
      if (pid < 0) {
         die_err("Error on fork");
      }
      
      if (pid == 0) {
         /* This is the client process */
         close(sockfd);
         handle_connection(newsockfd);
         exit(0);
      }
      else {
         close(newsockfd);
      }
        
   } /* end of while */
}
