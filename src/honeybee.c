#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include "honeybee.h"

/**
 * Simple C honeypot.
 *
 * @copyright Copyright (C) 2016 ProfiWeb sro (http://profiweb.biz/).
 * @author Marian Tomlak
 * @license BSD
 */

int var_port = 0;
int var_debug = 0;
char *var_type = '\0';
const char *modes[MODE_COUNT];

/**
 * Outputs an error message end exits program with the error status code
 * 
 * @param char* errstr Error string
 */
void die_err(char *format, ...)
{
   char buf[(BUF_SZ + 1)];
   int bytes;

   va_list argptr;
   va_start(argptr, format);

   if (vsnprintf(buf, BUF_SZ, format, argptr) == -1) {
      die_err("stream_write() -- vsnprintf() failed");
   }
   va_end(argptr);

   perror(buf);
   exit(1);
}

/**
 * Writes formatted string to the stream, similar usage as sprintf().
 * 
 */
int stream_write(int sock, char *format, ...)
{
   char buf[(BUF_SZ + 1)];
   int bytes;

   va_list argptr;
   va_start(argptr, format);

   if (vsnprintf(buf, BUF_SZ, format, argptr) == -1) {
      die_err("stream_write() -- vsnprintf() failed");
   }
   va_end(argptr);

   bytes = write(sock, buf, strlen(buf));
   
   if (bytes < 0) {
      die_err("stream_write() -- ERROR writing to socket");
   }
   if (var_debug)
      printf("OUT: %s\n", buf);

   return bytes;
}

/**
 * Reads from stream to the given buffer of specified size
 * 
 */
int stream_read(int sock, char* buf, int buf_size)
{
   int bytes;

   bytes = read(sock, buf, buf_size);

   if (bytes < 0) {
      die_err("stream_read() -- ERROR reading from socket");
   }
   if (var_debug)
      printf("IN: %s\n", buf);

   return bytes;
}


/**
 * Writes a message about an event to the syslog or a log file
 * 
 */
void log_event(int priority, char *format, ...)
{
   char buf[(BUF_SZ + 1)];
   va_list ap;

   va_start(ap, format);
   (void)vsnprintf(buf, BUF_SZ, format, ap);
   va_end(ap);

   FILE *fp;

   if((fp = fopen("/tmp/honeybee.log", "a")) != (FILE *)NULL) {
      (void)fprintf(fp, "%s\n", buf);
      (void)fclose(fp);
   }
   else {
      (void)fprintf(stderr, "Can't write to /tmp/honeybee.log\n");
   }

#if HAVE_SYSLOG_H
#if OLDSYSLOG
   openlog(APP_NAME, LOG_PID);
#else
   openlog(APP_NAME, LOG_PID, LOG_MAIL);
#endif
   syslog(priority, "%s", buf);
   closelog();
#endif
}

/**
 * Prints out usage help
 */
void print_help(char *self)
{
   printf("ProfIWeb Honeybee honeypot version %s\n\n", APP_VERSION);
   printf("Usage : %s [ -a | -m <mode> ] [ -dhpv ]\n", self);
   printf("\t-a starts daemons for all modes\n");
   printf("\t-d goes daemon\n\t-h prints this help\n");
   printf("\t-m sets honeypot mode, available modes - with name and port:\n");
   printf("\t\tcisco-fingerd\t\tCisco fingerd\t\t\t\t2003\n");
   printf("\t\tcisco-telnet-fire\tCisco PIX 500 series telnetd\t\t5999\n");
   printf("\t\tcisco-telnet-fire2\tCisco telnetd (IOS 6.X)\t\t\t5998\n");
   printf("\t\tcisco-http-fire\t\tCisco ASA firewall http config\t\t5911\n");
   printf("\t\tcisco-lm\t\tCisco CallManager license manager 6\t5910\n");
   printf("\t\tcisco-sccp\t\tCisco CallManager SCCP v12\t\t2000\n");
   printf("\t\tcisco-smi\t\tCisco Smart Install Client\t\t4786\n");
   printf("\t\tcisco-sip\t\tCisco SIP Gateway\t\t\t5060\n");
   printf("\t\tcisco-tftp\t\tCisco TFTP server\t\t\t69\n");
   printf("\t\tcisco-snmp\t\tCisco SNMP agent\t\t\t161\n");
   printf("\t\tcisco-ike\t\tCisco VPN 3000 concentrator\t500\n");
   printf("\t\tms-ldap-gc\t\tActive Directory LDAP\t\t3268\n");
   printf("\t\tms-rpc-dynamic\tMicrosoft Windows RPC\t\t49152\n");
   printf("\t\tapple-ard\t\tApple ARD agent\t\t\t5555\n");
   printf("\t\tapple-daap\t\tApple iTunes DAAP sharing\t3689\n");
   printf("\t\tibm-mqtt-tls\t\tIBM MessageSight MQTT\t\t8883\n");
   printf("\t\tvmware-vami\t\tVMware vCenter VAMI\t\t9443\n");
   printf("\t\toracle-app-manager\tOracle Application Server 11g httpd\t5988\n");
   printf("\t\toracle-rmi-lite\t\tOracle Database Lite RMI\t\t5987\n");
   printf("\t-p force specific port number (defaults according to module)\n");
   printf("\t-v enters verbose (debug) mode (currently %s)\n\n", 
      var_debug ? "ON" : "OFF");
}

int get_port_for_type(char *honey_type)
{
   // Determine default port number for each type of honeypot
   if (strcmp(honey_type, "cisco-telnet-fire") == 0) {
      return 5999;

   } else if (strcmp(honey_type, "cisco-telnet-fire2") == 0) {
      return 5998;

   } else if (strcmp(honey_type, "cisco-fingerd") == 0) {
      return 2003;

   } else if (strcmp(honey_type, "cisco-http-fire") == 0) {
      return 5911;

   } else if (strcmp(honey_type, "oracle-rmi-lite") == 0) {
      return 5987;   // 3891 could be good guess

   } else if (strcmp(honey_type, "oracle-app-manager") == 0) {
      return 5988;

   } else if (strcmp(honey_type, "cisco-lm") == 0) {
      return 5910;

   } else if (strcmp(honey_type, "cisco-sccp") == 0) {
      return 2000;

   } else if (strcmp(honey_type, "cisco-smi") == 0) {
      return 4786;

   } else if (strcmp(honey_type, "cisco-sip") == 0) {
      return 5060;

   } else if (strcmp(honey_type, "cisco-tftp") == 0) {
      return 69;

   } else if (strcmp(honey_type, "cisco-snmp") == 0) {
      return 161;

   } else if (strcmp(honey_type, "cisco-ike") == 0) {
      return 500;

   } else if (strcmp(honey_type, "ms-ldap-gc") == 0) {
      return 3268;

   } else if (strcmp(honey_type, "ms-rpc-dynamic") == 0) {
      return 49152;

   } else if (strcmp(honey_type, "apple-ard") == 0) {
      return 5555;

   } else if (strcmp(honey_type, "apple-daap") == 0) {
      return 3689;

   } else if (strcmp(honey_type, "ibm-mqtt-tls") == 0) {
      return 8883;

   } else if (strcmp(honey_type, "vmware-vami") == 0) {
      return 9443;

   } else {
      die_err("Unsupported mode: %s", honey_type);
   }
}         

void init_modes()
{
   modes[CISCO_TELNET_FIRE]   = CISCO_TELNET_FIRE_S;
   modes[CISCO_TELNET_FIRE2]  = CISCO_TELNET_FIRE2_S;
   modes[CISCO_FINGERD]       = CISCO_FINGERD_S;
   modes[CISCO_HTTP_FIRE]     = CISCO_HTTP_FIRE_S;
   modes[ORACLE_RMI_LITE]     = ORACLE_RMI_LITE_S;
   modes[ORACLE_APP_MANAGER]  = ORACLE_APP_MANAGER_S;
   modes[CISCO_LM]            = CISCO_LM_S;
   modes[CISCO_SCCP]          = CISCO_SCCP_S;
   modes[CISCO_SMI]           = CISCO_SMI_S;
   modes[CISCO_SIP]           = CISCO_SIP_S;
   modes[CISCO_TFTP]          = CISCO_TFTP_S;
   modes[CISCO_SNMP]          = CISCO_SNMP_S;
   modes[CISCO_IKE]           = CISCO_IKE_S;
   modes[MS_LDAP_GC]          = MS_LDAP_GC_S;
   modes[MS_RPC_DYNAMIC]      = MS_RPC_DYNAMIC_S;
   modes[APPLE_ARD]           = APPLE_ARD_S;
   modes[APPLE_DAAP]          = APPLE_DAAP_S;
   modes[IBM_MQTT_TLS]        = IBM_MQTT_TLS_S;
   modes[VMWARE_VAMI]         = VMWARE_VAMI_S;
}


/**
 * Main program handler
 * 
 * @param  int argc
 * @param  char* argv
 * @return int
 */
int main(int argc, char *argv[]) 
{
   int opt, pid, i, daemon = 0, all = 0;

   init_modes();

   if (argc > 1) { 
   // Set some config variables
      while((opt = getopt(argc, argv, "am:dhp:v")) != -1) {
         switch(opt) {
            // This should always be first arguments
            case 'a':
               all = 1;
               daemon = 1;
               break;
            case 'm':
               var_type = strdup(optarg);
               var_port = get_port_for_type(var_type);
               if (all) {
                  printf("Warning: Ignoring arument -a\n");
                  all = 0;
               }
               break;
            // Optional arguments
            case 'd':
               daemon = 1;
               break;
            case 'h':
               print_help(argv[0]);
               exit(0);
            case 'p':
               var_port = atoi(optarg);
               break;
            case 'v':
               printf("Entering verbose mode\n");
               var_debug = 1;
               break;
            default:
               break;
         }
      }
   } else {
      print_help(argv[0]);
      exit(1);
   }

   // Start the server, possibly in a background
   if (daemon) {
      if (all) {
         for (i = 0; i < MODE_COUNT; ++i) {
            var_type = strdup(modes[i]);
            var_port = get_port_for_type(var_type);

            printf("Starting %s %s daemon on port %d\n", APP_NAME, var_type, var_port);
            pid = fork();

            if (pid < 0)
               die_err("Error on fork");

            if (pid == 0) {   // We are in child process
               server_start(var_port);
               exit(0);
            }
         }
      } else {
         printf("Starting %s %s daemon on port %d\n", APP_NAME, var_type, var_port);
         pid = fork();

         if (pid < 0)
            die_err("Error on fork");

         if (pid == 0) {   // We are in child process
            server_start(var_port);
            exit(0);
         }
      }
   } else {
      printf("Starting %s %s daemon on port %d\n", APP_NAME, var_type, var_port);
      server_start(var_port);
   }

   exit(0);
}
