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
#include "agent.h"

void agent_gather_candidates(Agent *agent) {

  Address addr;

  stun_get_local_address(STUN_IP, STUN_PORT, &addr);

  char buffer[1024];

  memset(buffer, 0, sizeof(buffer));

  ice_candidate_create(&agent->local_candidates[0], ICE_CANDIDATE_TYPE_SRFLX, &addr);

}

void agent_get_local_description(Agent *agent, char *description, int length) {

  char ufrag[ICE_UFRAG_LENGTH + 1];

  char upwd[ICE_UPWD_LENGTH + 1];

  memset(description, 0, length);

  memset(ufrag, 0, sizeof(ufrag));

  memset(upwd, 0, sizeof(upwd));

  utils_random_string(ufrag, ICE_UFRAG_LENGTH);

  utils_random_string(upwd, ICE_UPWD_LENGTH);

  snprintf(description, length, "m=text 60083 ICE/SDP\na=ice-ufrag:%s\na=ice-pwd:%s\n", ufrag, upwd);

  char buffer[1024];

  memset(buffer, 0, sizeof(buffer));

  ice_candidate_to_description(&agent->local_candidates[0], buffer, sizeof(buffer));

  strncat(description, buffer, length - strlen(description) - 1);

  udp_socket_open(&agent->udp_socket, &agent->local_candidates[0].address);
}

void agent_send(Agent *agent, char *buf, int len) {

  printf("send to ip: %d.%d.%d.%d:%d\n", agent->remote_candidates[8].address.ipv4[0], agent->remote_candidates[8].address.ipv4[1], agent->remote_candidates[8].address.ipv4[2], agent->remote_candidates[8].address.ipv4[3], agent->remote_candidates[8].address.port);
#if 0
  agent->remote_candidates[8].address.ipv4[8] = 0;
  agent->remote_candidates[0].address.ipv4[1] = 0;
  agent->remote_candidates[0].address.ipv4[2] = 0;
  agent->remote_candidates[0].address.ipv4[3] = 0;
#endif
  udp_socket_sendto(&agent->udp_socket, &agent->remote_candidates[8].address, buf, len);

}

void agent_recv(Agent *agent) {

  char buf[1024];

  printf("Listening port: %d\n", agent->local_candidates[0].address.port);

  if (udp_socket_recvfrom(&agent->udp_socket, &agent->local_candidates[0].address, buf, sizeof(buf)) > 0) {

    LOGD("recvfrom: %s", buf);
  }

}



void agent_set_remote_description(Agent *agent, char *description) {

/*
a=ice-ufrag:Iexb
a=ice-pwd:IexbSoY7JulyMbjKwISsG9
a=candidate:1 1 UDP 1 36.231.28.50 38143 typ srflx
*/

  LOGD("Set remote description:\n%s", description);

  char *line = strtok(description, "\r\n");

  while (line) {

    if (strncmp(line, "a=ice-ufrag:", strlen("a=ice-ufrag:")) == 0) {

      agent->ice_ufrag = strdup(line + strlen("a=ice-ufrag:"));

    } else if (strncmp(line, "a=ice-pwd:", strlen("a=ice-pwd:")) == 0) {

      agent->ice_upwd = strdup(line + strlen("a=ice-pwd:"));

    } else if (strncmp(line, "a=candidate:", strlen("a=candidate:")) == 0) {

      ice_candidate_from_description(&agent->remote_candidates[agent->remote_candidates_count++], line);
    }

    line = strtok(NULL, "\r\n");
  }

  LOGD("ice_ufrag: %s", agent->ice_ufrag);
  LOGD("ice_upwd: %s", agent->ice_upwd);

}

void *agent_thread(void *arg) {

  Agent *agent = (Agent *)arg;

  agent_recv(agent);

  return NULL;
}

