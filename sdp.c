#include <stdio.h>
#include <stdarg.h>

#include "sdp.h"

int sdp_append(Sdp *sdp, const char *format, ...) {

  va_list argptr;

  char attr[SDP_ATTR_LENGTH];

  memset(attr, 0, sizeof(attr));

  va_start(argptr, format);

  vsnprintf(attr, sizeof(attr), format, argptr);

  va_end(argptr);

  strcat(sdp->content, attr);
  strcat(sdp->content, "\r\n");

}

void sdp_reset(Sdp *sdp) {

  memset(sdp->content, 0, sizeof(sdp->content));
}

void sdp_append_h264(Sdp *sdp) {

  sdp_append(sdp, "m=video 9 UDP/TLS/RTP/SAVPF 96 102");
  sdp_append(sdp, "a=rtcp-fb:102 nack");
  sdp_append(sdp, "a=rtcp-fb:102 nack pli");
  sdp_append(sdp, "a=fmtp:96 profile-level-id=42e01f;level-asymmetry-allowed=1");
  sdp_append(sdp, "a=fmtp:102 profile-level-id=42e01f;packetization-mode=1;level-asymmetry-allowed=1");
  sdp_append(sdp, "a=rtpmap:96 H264/90000");
  sdp_append(sdp, "a=rtpmap:102 H264/90000");
  sdp_append(sdp, "a=ssrc:1 cname:webrtc-video");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:0");
  sdp_append(sdp, "a=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_pcma(Sdp *sdp) {

  sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 8");
  sdp_append(sdp, "a=rtpmap:8 PCMA/8000");
}

void sdp_append_datachannel(Sdp *sdp) {

  sdp_append(sdp, "m=application 50712 UDP/DTLS/SCTP webrtc-datachannel");
  sdp_append(sdp, "a=sctp-port:5000");
  sdp_append(sdp, "a=max-message-size:262144");
}

void sdp_create(Sdp *sdp) {


  sdp_append(sdp, "v=0");
  sdp_append(sdp, "o=- 1495799811084970 1495799811084970 IN IP4 0.0.0.0");
  sdp_append(sdp, "s=-");
  sdp_append(sdp, "t=0 0");
  sdp_append(sdp, "a=msid-semantic: iot");
  sdp_append(sdp, "a=group:BUNDLE 0");
}

