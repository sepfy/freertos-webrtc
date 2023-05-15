#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

void sdp_test() {

  char remote_description[AGENT_MAX_DESCRIPTION];
  char remote_description_base64[AGENT_MAX_DESCRIPTION];
  char local_description[AGENT_MAX_DESCRIPTION];
  char local_description_base64[AGENT_MAX_DESCRIPTION];

  memset(remote_description, 0, sizeof(remote_description));
  memset(remote_description_base64, 0, sizeof(remote_description_base64));

  printf("Enter remote description base64: \n");
  scanf("%s", remote_description_base64);

  base64_decode(remote_description_base64, strlen(remote_description_base64), remote_description, sizeof(remote_description));

  printf("Remote description: \n%s", remote_description);

  Agent agent;

  memset(&agent, 0, sizeof(agent));

  agent_gather_candidates(&agent);

  agent_get_local_description(&agent, local_description, sizeof(local_description));

  base64_encode(local_description, strlen(local_description), local_description_base64, sizeof(local_description_base64));

  printf("Local description: \n%s", local_description);

  printf("Local description base64: \n%s\n", local_description_base64);

  agent_set_remote_description(&agent, remote_description);
#if 0
  pthread_t thread;

  pthread_create(&thread, NULL, agent_thread, &agent);

  sleep(1);

  char buf[] = "hello";

  while(1) {

    agent_send(&agent, buf, sizeof(buf));
    sleep(1);
  }

  return 0;
#endif
}

int main(int argc, char *argv[]) {

  sdp_test();

  return 0;
}
