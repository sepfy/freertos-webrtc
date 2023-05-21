#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "udp.h"
#include "utils.h"
#include "ice.h"

void ice_candidate_create(IceCandidate *candidate, IceCandidateType type, Address *addr) {

  memcpy(&candidate->address, addr, sizeof(Address));

  candidate->port = addr->port; 

  candidate->type = type;

  candidate->foundation = 1;

  candidate->priority = 1;

  candidate->component = 1;

  snprintf(candidate->transport, sizeof(candidate->transport), "%s", "UDP");
}

void ice_candidate_to_description(IceCandidate *candidate, char *description, int length) {

  char type_text[16];

  memset(description, 0, length);

  memset(type_text, 0, sizeof(type_text));

  switch (candidate->type) {

    case ICE_CANDIDATE_TYPE_HOST:
      snprintf(type_text, sizeof(type_text), "host");
      break;

    case ICE_CANDIDATE_TYPE_SRFLX:
      snprintf(type_text, sizeof(type_text), "srflx");
      break;

    default:
      break;
  }

  snprintf(description, length, "a=candidate:%d %d %s %ld %d.%d.%d.%d %d typ %s",
   candidate->foundation,
   candidate->component,
   candidate->transport,
   candidate->priority,
   candidate->address.ipv4[0],
   candidate->address.ipv4[1],
   candidate->address.ipv4[2],
   candidate->address.ipv4[3],
   candidate->port,
   type_text);
}

int ice_candidate_from_description(IceCandidate *candidate, char *description) {

  char type[16];

  if (sscanf(description, "a=candidate:%d %d %s %ld %hhu.%hhu.%hhu.%hhu %hd typ %s",
   &candidate->foundation,
   &candidate->component,
   candidate->transport,
   &candidate->priority,
   &candidate->address.ipv4[0],
   &candidate->address.ipv4[1],
   &candidate->address.ipv4[2],
   &candidate->address.ipv4[3],
   &candidate->address.port,
   type) != 10) {

    LOGE("Failed to parse candidate description: %s", description);
    return -1;
  }

  if (strcmp(type, "host") == 0) {

    candidate->type = ICE_CANDIDATE_TYPE_HOST;

  } else if (strcmp(type, "srflx") == 0) {

    candidate->type = ICE_CANDIDATE_TYPE_SRFLX;

  } else {

    LOGE("Unknown candidate type: %s", type);
    return -1;
  }

  return 0;
}

