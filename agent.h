#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <pthread.h>

#include "udp.h"
#include "utils.h"
#include "stun.h"
#include "ice.h"
#include "base64.h"

#define STUN_IP "142.250.21.127"
#define STUN_PORT 19302

#define AGENT_MAX_DESCRIPTION 40960
#define AGENT_MAX_CANDIDATES 10

typedef struct Agent Agent;

struct Agent {

  char *ice_ufrag;

  char *ice_upwd;

  IceCandidate local_candidates[AGENT_MAX_CANDIDATES];

  IceCandidate remote_candidates[AGENT_MAX_CANDIDATES];

  int local_candidates_count;

  int remote_candidates_count;

  UdpSocket udp_socket;
  
};

void agent_gather_candidates(Agent *agent);

void agent_get_local_description(Agent *agent, char *description, int length);

void agent_send(Agent *agent, char *buf, int len);

void agent_recv(Agent *agent);

void agent_set_remote_description(Agent *agent, char *description);

void *agent_thread(void *arg);

