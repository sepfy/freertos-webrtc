#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#include "udp.h"
#include "utils.h"
#include "ice.h"

static void ice_candidate_calculate_priority(IceCandidate *candidate) {

  // priority = (2^24)*(type preference) + (2^8)*(local preference) + (256 - component ID)

  switch (candidate->type) {

    case ICE_CANDIDATE_TYPE_HOST:
      candidate->priority = 2130706432 + 16777215 + (256 - candidate->component);
      break;

    case ICE_CANDIDATE_TYPE_SRFLX:
      candidate->priority = 1694498815 + 16777215 + (256 - candidate->component);
      break;

    default:
      break;
  }

}

void ice_candidate_create(IceCandidate *candidate, IceCandidateType type, Address *addr) {

  memcpy(&candidate->addr, addr, sizeof(Address));

  candidate->type = type;

  candidate->foundation = 1;
  // 1: RTP, 2: RTCP
  candidate->component = 1;

  ice_candidate_calculate_priority(candidate);

  snprintf(candidate->transport, sizeof(candidate->transport), "%s", "UDP");
}

void ice_candidate_to_description(IceCandidate *candidate, char *description, int length) {

  char typ_raddr[64];

  memset(description, 0, length);

  memset(typ_raddr, 0, sizeof(typ_raddr));

  switch (candidate->type) {

    case ICE_CANDIDATE_TYPE_HOST:
      snprintf(typ_raddr, sizeof(typ_raddr), "host");
      break;

    case ICE_CANDIDATE_TYPE_SRFLX:
      snprintf(typ_raddr, sizeof(typ_raddr), "srflx raddr %d.%d.%d.%d rport %d",
       candidate->raddr.ipv4[0],
       candidate->raddr.ipv4[1],
       candidate->raddr.ipv4[2],
       candidate->raddr.ipv4[3],
       candidate->raddr.port);
      break;

    default:
      break;
  }

  snprintf(description, length, "a=candidate:%d %d %s %" PRIu32 " %d.%d.%d.%d %d typ %s\n",
   candidate->foundation,
   candidate->component,
   candidate->transport,
   candidate->priority,
   candidate->addr.ipv4[0],
   candidate->addr.ipv4[1],
   candidate->addr.ipv4[2],
   candidate->addr.ipv4[3],
   candidate->addr.port,
   typ_raddr);
}

int ice_candidate_from_description(IceCandidate *candidate, char *description) {

  char type[16];

  if (sscanf(description, "a=candidate:%d %d %s %" SCNu32 " %hhu.%hhu.%hhu.%hhu %hd typ %s",
   &candidate->foundation,
   &candidate->component,
   candidate->transport,
   &candidate->priority,
   &candidate->addr.ipv4[0],
   &candidate->addr.ipv4[1],
   &candidate->addr.ipv4[2],
   &candidate->addr.ipv4[3],
   &candidate->addr.port,
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

