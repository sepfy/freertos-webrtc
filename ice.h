#ifndef ICE_H_
#define ICE_H_

#include <stdlib.h>

#include "address.h"
#include "stun.h"

#define ICE_UFRAG_LENGTH 4
#define ICE_UPWD_LENGTH 22

typedef enum IceCandidateType {

  ICE_CANDIDATE_TYPE_HOST,

  ICE_CANDIDATE_TYPE_SRFLX,

} IceCandidateType;

typedef struct IceCandidate IceCandidate;

struct IceCandidate {
   
  IceCandidateType type;
   
  uint32_t priority;
   
  int component;

  int foundation;
    
  char transport[32 + 1];

  uint16_t port;

  Address address;
};

void ice_candidate_create(IceCandidate *ice_candidate, IceCandidateType type, Address *addr);

void ice_candidate_to_description(IceCandidate *candidate, char *description, int length);

int ice_candidate_from_description(IceCandidate *candidate, char *description);

int ice_candidate_get_local_address(IceCandidate *candidate, Address *address);

#endif // ICE_H_
