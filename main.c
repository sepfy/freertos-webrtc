#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdp.h"
#include "dtls_srtp.h"
#include "agent.h"

#include <cjson/cJSON.h>

//#define TEST_STUN
#define TEST_SDP
//#define TEST_DTLS
//#define TEST_OFFER

void test_stun() {

  Address local_addr;
  stun_get_local_address(STUN_IP, STUN_PORT, &local_addr);
}

void test_offer() {

  cJSON *offer = cJSON_CreateObject();

  Agent agent;

  char remote_description[AGENT_MAX_DESCRIPTION];
  char local_description[AGENT_MAX_DESCRIPTION];
  char offer_base64[AGENT_MAX_DESCRIPTION];
  char answer_base64[AGENT_MAX_DESCRIPTION];

  memset(remote_description, 0, sizeof(remote_description));

  memset(local_description, 0, sizeof(local_description));
  memset(offer_base64, 0, sizeof(offer_base64));

  memset(&agent, 0, sizeof(agent));

  agent_gather_candidates(&agent);

  agent_get_local_description(&agent, local_description, sizeof(local_description));

  Sdp sdp;

  sdp_create(&sdp);

  sdp_append_h264(&sdp);

  DtlsSrtp dtls_srtp;

  dtls_srtp_init(&dtls_srtp, NULL, DTLS_SRTP_ROLE_CLIENT);

  sdp_append(&sdp, "a=fingerprint:sha-256 %s", dtls_srtp.local_fingerprint);
  sdp_append(&sdp, "a=setup:actpass");
  strcat(sdp.content, local_description);

  printf("sdp: \n%s\n", sdp.content);

  // create offer
  cJSON_AddStringToObject(offer, "type", "offer");
  cJSON_AddStringToObject(offer, "sdp", sdp.content);
  
  char *offer_str = cJSON_Print(offer);

  printf("Offer: \n%s\n", offer_str);

  base64_encode(offer_str, strlen(offer_str), offer_base64, sizeof(offer_base64)); 

  printf("Offer base64: \n%s\n", offer_base64);

  free(offer_str);
  cJSON_Delete(offer);

  scanf("%s", answer_base64);

  char answer_str[AGENT_MAX_DESCRIPTION];

  base64_decode(answer_base64, strlen(answer_base64), answer_str, sizeof(answer_str));

  cJSON *answer = cJSON_Parse(answer_str);

  char *answer_sdp = cJSON_GetObjectItem(answer, "sdp")->valuestring;

  printf("Answer SDP: \n%s\n", answer_sdp);

  agent_set_remote_description(&agent, answer_sdp);

  for(int i = 0; i < agent.remote_candidates_count; i++) {

		printf("Remote candidate: %d ip = %d.%d.%d.%d port = %d\n", i, agent.remote_candidates[i].addr.ipv4[0], agent.remote_candidates[i].addr.ipv4[1], agent.remote_candidates[i].addr.ipv4[2], agent.remote_candidates[i].addr.ipv4[3], agent.remote_candidates[i].addr.port);
	}

  cJSON_Delete(answer);
}

void test_sdp(int argc, char *argv[]) {

  Agent agent;

  char remote_description[AGENT_MAX_DESCRIPTION];
  char remote_description_base64[AGENT_MAX_DESCRIPTION];
  char local_description[AGENT_MAX_DESCRIPTION];
  char local_description_base64[AGENT_MAX_DESCRIPTION];

  if (argc < 2) {

    printf("Usage: %s peer_id\n", argv[0]);
    return;
  }

  memset(remote_description, 0, sizeof(remote_description));
  memset(remote_description_base64, 0, sizeof(remote_description_base64));

  memset(local_description, 0, sizeof(local_description));
  memset(local_description_base64, 0, sizeof(local_description_base64));

  memset(&agent, 0, sizeof(agent));

  agent_gather_candidates(&agent);

  snprintf(local_description, sizeof(local_description), "m=text 50327 ICE/SDP\nc=IN IP4 0.0.0.0\n");

  agent_get_local_description(&agent, local_description + strlen(local_description), sizeof(local_description));

  base64_encode(local_description, strlen(local_description), local_description_base64, sizeof(local_description_base64));

  printf("Local description: \n%s\n", local_description);

  printf("Local description base64: \n%s\n", local_description_base64);

  printf("Enter remote description base64: \n");

  scanf("%s", remote_description_base64);

  base64_decode(remote_description_base64, strlen(remote_description_base64), remote_description, sizeof(remote_description));

  printf("Remote description: \n%s", remote_description);

  agent_set_remote_description(&agent, remote_description);

  pthread_t thread;

  pthread_create(&thread, NULL, agent_thread, &agent);

  char buf[64];

  memset(buf, 0, sizeof(buf));

  snprintf(buf, sizeof(buf), "hello from %s", argv[1]);

  while(1) {

    agent_select_candidate_pair(&agent);
//    agent_send(&agent, buf, sizeof(buf));
    usleep(1000 * 1000);
  }

}

void test_dtls(int argc, char *argv[]) {

  DtlsSrtp dtls_srtp;
  UdpSocket udp_socket;
  Address local_addr;
  Address remote_addr;


  if (argc < 2) {

    printf("Usage: %s client/server\n", argv[0]);
    return;
  }

  local_addr.ipv4[0] = 192;
  local_addr.ipv4[1] = 168;
  local_addr.ipv4[2] = 1;
  local_addr.ipv4[3] = 110;

  remote_addr.ipv4[0] = 192;
  remote_addr.ipv4[1] = 168;
  remote_addr.ipv4[2] = 1;
  remote_addr.ipv4[3] = 110;

  if (strstr(argv[1], "client")) {

    local_addr.port = 1234;
    remote_addr.port = 5678;
    dtls_srtp_init(&dtls_srtp, &udp_socket,  DTLS_SRTP_ROLE_CLIENT);

  } else {

    local_addr.port = 5678;
    remote_addr.port = 1234;
    dtls_srtp_init(&dtls_srtp, &udp_socket, DTLS_SRTP_ROLE_SERVER);
  }

  udp_socket_open(&udp_socket);

  udp_socket_bind(&udp_socket, &local_addr);

  dtls_srtp_handshake(&dtls_srtp, &remote_addr);

  char buf[64];

  memset(buf, 0, sizeof(buf));

  if (strstr(argv[1], "client")) {

    snprintf(buf, sizeof(buf), "hello from client");

    printf("client sending: %s\n", buf);

    usleep(100 * 1000);

    dtls_srtp_write(&dtls_srtp, buf, sizeof(buf));

    dtls_srtp_read(&dtls_srtp, buf, sizeof(buf));

    printf("client received: %s\n", buf);

  } else {

    dtls_srtp_read(&dtls_srtp, buf, sizeof(buf));

    printf("server received: %s\n", buf);

    snprintf(buf, sizeof(buf), "hello from server");

    printf("server sending: %s\n", buf);

    usleep(100 * 1000);

    dtls_srtp_write(&dtls_srtp, buf, sizeof(buf));

  }

}

void test_local() {

  char description1[AGENT_MAX_DESCRIPTION];
  char description2[AGENT_MAX_DESCRIPTION];

  Agent agent1;
  Agent agent2;

  memset(&agent1, 0, sizeof(agent1));
  memset(&agent2, 0, sizeof(agent2));
  memset(description1, 0, sizeof(description1));
  memset(description2, 0, sizeof(description2));

  agent_gather_candidates(&agent1);

  agent_get_local_description(&agent1, description1, sizeof(description1));

  agent_set_remote_description(&agent2, description1);

  agent_gather_candidates(&agent2);

  agent_get_local_description(&agent2, description2, sizeof(description2));

  agent_set_remote_description(&agent1, description2);

  pthread_t thread1;

  pthread_t thread2;

  pthread_create(&thread1, NULL, agent_thread, &agent1);

  pthread_create(&thread2, NULL, agent_thread, &agent2);

  sleep(1);

  char buf[] = "hello";

  while(1) {

    agent_send(&agent1, buf, sizeof(buf));
    agent_send(&agent2, buf, sizeof(buf));
    usleep(1000 * 1000);
  }
}

int main(int argc, char *argv[]) {

#ifdef TEST_OFFER
  test_offer();
#endif

#ifdef TEST_DTLS
  test_dtls(argc, argv);
#endif

#ifdef TEST_SDP
  test_sdp(argc, argv);
#endif

#ifdef TEST_STUN
  test_stun();
#endif

  //test_local();
  return 0;
}
