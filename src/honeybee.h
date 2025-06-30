#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define APP_NAME "HoneyBee"
#define APP_VERSION "0.193"
#define BUF_SZ 1024

#define CISCO_TELNET_FIRE_S   "cisco-telnet-fire"
#define CISCO_TELNET_FIRE2_S  "cisco-telnet-fire2" 
#define CISCO_FINGERD_S       "cisco-fingerd"  
#define CISCO_HTTP_FIRE_S     "cisco-http-fire"
#define ORACLE_RMI_LITE_S     "oracle-rmi-lite"
#define ORACLE_APP_MANAGER_S  "oracle-app-manager"
#define CISCO_LM_S            "cisco-lm"
#define CISCO_SCCP_S          "cisco-sccp"
#define CISCO_SMI_S           "cisco-smi"
#define CISCO_SIP_S           "cisco-sip"
#define CISCO_TFTP_S          "cisco-tftp"
#define CISCO_SNMP_S          "cisco-snmp"
#define CISCO_IKE_S           "cisco-ike"
#define MS_LDAP_GC_S          "ms-ldap-gc"
#define MS_RPC_DYNAMIC_S      "ms-rpc-dynamic"
#define APPLE_ARD_S           "apple-ard"
#define APPLE_DAAP_S          "apple-daap"
#define IBM_MQTT_TLS_S        "ibm-mqtt-tls"
#define VMWARE_VAMI_S         "vmware-vami"

#define CISCO_TELNET_FIRE     0
#define CISCO_TELNET_FIRE2    1
#define CISCO_FINGERD         2
#define CISCO_HTTP_FIRE       3
#define ORACLE_RMI_LITE       4
#define ORACLE_APP_MANAGER    5
#define CISCO_LM              6
#define CISCO_SCCP            7
#define CISCO_SMI             8
#define CISCO_SIP             9
#define CISCO_TFTP            10
#define CISCO_SNMP            11
#define CISCO_IKE             12
#define MS_LDAP_GC            13
#define MS_RPC_DYNAMIC        14
#define APPLE_ARD             15
#define APPLE_DAAP            16
#define IBM_MQTT_TLS          17
#define VMWARE_VAMI           18

#define MODE_COUNT            19

extern int var_port;
extern int var_debug;
extern char *var_type;
extern const char *modes[MODE_COUNT];

struct conn_state{
   int sock;
   int cmd_count;
   int last_cmd_id;
};

void die_err(char *format, ...);
int stream_write(int sock, char *format, ...);
int stream_read(int sock, char* buf, int buf_size);
void log_event(int priority, char *format, ...);
// server.c
int server_start(int port_num);
// connection.c
void handle_connection(int sock);
