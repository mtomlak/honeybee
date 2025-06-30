#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include "honeybee.h"

#define CMD_NONE        0
#define CMD_AUTH_PASS   2

/**
 * Handles Cloud Simple RMI protocol and server side communication.
 *
 * @copyright Copyright (C) 2016 ProfiWeb sro (http://profiweb.biz/).
 * @project honeybee
 * @author Marian Tomlak
 * @license BSD
 */

// External config variables
extern int var_debug;
extern char *var_type;


void cisco_telnet_fire1_banner(int sock)
{
   stream_write(sock, "\xff\xfb\x01\r\r\nUser Access Verification\r\r\n\r\r\nUsername: ");  
}

void cisco_telnet_fire2_banner(int sock)
{
   stream_write(sock, "\xff\xfb\x03\xff\xfb\x01\xff\xfb\x03\xff\xfb\x01.*\r\nUser Access Verification\r\n\r\n");  
}

void cisco_fingerd_banner(int sock)
{
   stream_write(sock, "\r\n\x20\x20\x20\x20Line\x20 \x20 \x20User \x20 \x20 \x20Host(s) \x20 \x20 \x20 \x20 \x20 \x20 \x20 \x20 \x20Idle Location\r\n");
}

void cisco_http_fire_banner(int sock)
{
   stream_write(sock, "HTTP/1.0 302 Object Moved\r\nServer: Cisco AWARE ctx.n2\r\n\r\n");  
}

void cisco_lm6_banner(int sock) //5038 
{
   stream_write(sock, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LicXmlDoc><MessageType><ParamValue>RESPONSE</ParamValue></MessageType><OperationCode><ParamValue>4923</ParamValue></OperationCode></LicXmlDoc>");  
}

void oracle_app_manager_banner(int sock)
{
   stream_write(sock, "HTTP/1.1 200 OK\r\n.*Server: Oracle-Application-Server-11g\r\nAllow: GET,HEAD,POST,OPTIONS\r\nContent-Length: 0\r\n");  
}

void oracle_rmi_lite_banner(int sock)
{
   write(sock, "\0\0\xfa\xda\0\x02", 6);
}

void cisco_sccp_banner(int sock)
{
   stream_write(sock, "SCCP Cisco CallManager 12.0\r\n");
}

void cisco_smi_banner(int sock)
{
   unsigned char msg[] = {0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01};
   write(sock, msg, sizeof(msg));
}

void cisco_sip_banner(int sock)
{
   stream_write(sock, "SIP/2.0 200 OK\r\nServer: Cisco-SIPGateway\r\n\r\n");
}

void cisco_tftp_banner(int sock)
{
   unsigned char msg[] = {0x00,0x05,0x00,0x00,'I','n','v','a','l','i','d',' ','T','F','T','P',' ','O','p','c','o','d','e'};
   write(sock, msg, sizeof(msg));
}

void cisco_snmp_banner(int sock)
{
   stream_write(sock, "SNMPv2-MIB::sysDescr.0 = STRING: Cisco IOS Software\r\n");
}

void cisco_ike_banner(int sock)
{
   stream_write(sock, "Cisco VPN 3000 concentrator\r\n");
}

void ms_ldap_gc_banner(int sock)
{
   stream_write(sock, "Active Directory LDAP\r\n");
}

void ms_rpc_dynamic_banner(int sock)
{
   stream_write(sock, "Microsoft Windows RPC\r\n");
}

void apple_ard_banner(int sock)
{
   stream_write(sock, "ARDAgent\r\n");
}

void apple_daap_banner(int sock)
{
   stream_write(sock, "HTTP/1.1 200 OK\r\nServer: DAAP\r\n\r\n");
}

void ibm_mqtt_tls_banner(int sock)
{
   stream_write(sock, "IBM MessageSight MQTT\r\n");
}

void vmware_vami_banner(int sock)
{
   stream_write(sock, "HTTP/1.1 200 OK\r\nServer: VMware VAMI\r\n\r\n");
}

int telnet_password_prompt(char *line, struct conn_state *state, int max_tries)
{
   if (state->cmd_count >= max_tries) {
      sleep(1);
      stream_write(state->sock, "Access denied\n");
      return 0;
   }

   if (state->last_cmd_id == CMD_NONE) {
      stream_write(state->sock, "Password: ");
      state->last_cmd_id = CMD_AUTH_PASS;

   } else {
      sleep(1);
      stream_write(state->sock, "Access denied\nPassword: ");
   }

   return 1;
}

/**
 * Handles a single socket connection to the client.
 * 
 */
void handle_connection (int sock) 
{
   int loop;
   char buf[(BUF_SZ + 1)];
   struct conn_state state;
   bzero(buf, BUF_SZ);
   // Initiate default values for state structure
   state.sock = sock;
   state.cmd_count = 0;
   state.last_cmd_id = CMD_NONE;

   // Cisco PIX 500 series telnetd
   if (strcmp(var_type, "cisco-telnet-fire") == 0) {
      cisco_telnet_fire1_banner(sock);

      do {
         stream_read(sock, buf, BUF_SZ);
         loop = telnet_password_prompt(buf, &state, 3);
         state.cmd_count++;
      } while (loop != 0);

   // Cisco telnetd (IOS 6.X)
   } else if (strcmp(var_type, "cisco-telnet-fire2") == 0) {
      cisco_telnet_fire2_banner(sock);
      telnet_password_prompt(buf, &state, 1);
      sleep(1);   // extra second for first auth..

      do {
         stream_read(sock, buf, BUF_SZ);
         loop = telnet_password_prompt(buf, &state, 2);
         state.cmd_count++;
      } while (loop != 0);

   } else if (strcmp(var_type, "cisco-fingerd") == 0) {
      cisco_fingerd_banner(sock);
      sleep(2);

   } else if (strcmp(var_type, "cisco-http-fire") == 0) {
      cisco_http_fire_banner(sock);
      sleep(2);

   } else if (strcmp(var_type, "oracle-rmi-lite") == 0) {
      oracle_rmi_lite_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "oracle-app-manager") == 0) {
      oracle_app_manager_banner(sock);
      sleep(2);

   } else if (strcmp(var_type, "cisco-lm") == 0) {
      cisco_lm6_banner(sock);
      sleep(2);

   } else if (strcmp(var_type, "cisco-sccp") == 0) {
      cisco_sccp_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "cisco-smi") == 0) {
      cisco_smi_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "cisco-sip") == 0) {
      cisco_sip_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "cisco-tftp") == 0) {
      cisco_tftp_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "cisco-snmp") == 0) {
      cisco_snmp_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "cisco-ike") == 0) {
      cisco_ike_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "ms-ldap-gc") == 0) {
      ms_ldap_gc_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "ms-rpc-dynamic") == 0) {
      ms_rpc_dynamic_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "apple-ard") == 0) {
      apple_ard_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "apple-daap") == 0) {
      apple_daap_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "ibm-mqtt-tls") == 0) {
      ibm_mqtt_tls_banner(sock);
      sleep(1);

   } else if (strcmp(var_type, "vmware-vami") == 0) {
      vmware_vami_banner(sock);
      sleep(1);

   } else {
      die_err("Unsupported mode: %s", var_type);
   }
}
