#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mbedtls/ssl.h"
#include "dtls_srtp.h"
#include "address.h"
#include "udp.h"
#include "utils.h"

#define CERT_BUF_SIZE 4096

int dtls_srtp_udp_send(void *ctx, const unsigned char *buf, size_t len) {

  DtlsSrtp *dtls_srtp = (DtlsSrtp *) ctx;

  int ret = udp_socket_sendto(dtls_srtp->udp_socket, dtls_srtp->remote_addr, (char*)buf, len);

  LOGD("dtls_srtp_udp_send (%d)", ret);

  return ret;
}

int dtls_srtp_udp_recv(void *ctx, unsigned char *buf, size_t len) {

  DtlsSrtp *dtls_srtp = (DtlsSrtp *) ctx;

  int ret = udp_socket_recvfrom(dtls_srtp->udp_socket, &dtls_srtp->udp_socket->bind_addr, (char*)buf, len);

  LOGD("dtls_srtp_udp_recv (%d)", ret);

  return ret;
}

static void dtls_srtp_x509_digest(const mbedtls_x509_crt *crt, char *buf) {

  int i;
  unsigned char digest[32];

  mbedtls_sha256_context sha256_ctx;
  mbedtls_sha256_init(&sha256_ctx);
  mbedtls_sha256_starts(&sha256_ctx, 0);
  mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
  mbedtls_sha256_finish(&sha256_ctx, (unsigned char *) digest);
  mbedtls_sha256_free(&sha256_ctx);

  for(i = 0; i < 32; i++) {

    snprintf(buf, 4, "%.2X:", digest[i]);
    buf += 3;
  }

  *(--buf) = '\0';
}

// Do not verify CA
static int dtls_srtp_cert_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {

  *flags &= ~(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_CN_MISMATCH);
  return 0;
}

static int dtls_srtp_selfsign_cert(DtlsSrtp *dtls_srtp) {

  int ret;

  mbedtls_x509write_cert crt;

  unsigned char cert_buf[CERT_BUF_SIZE];

  const char *pers = "dtls_srtp";

  mbedtls_ctr_drbg_seed(&dtls_srtp->ctr_drbg, mbedtls_entropy_func, &dtls_srtp->entropy, (const unsigned char *) pers, strlen(pers));

  mbedtls_pk_setup(&dtls_srtp->pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
 
  mbedtls_rsa_gen_key(mbedtls_pk_rsa(dtls_srtp->pkey), mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg, 2048, 65537);

  mbedtls_x509write_crt_init(&crt);

  mbedtls_x509write_crt_set_subject_key(&crt, &dtls_srtp->pkey);

  mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

  mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

  mbedtls_x509write_crt_set_subject_key(&crt, &dtls_srtp->pkey);

  mbedtls_x509write_crt_set_issuer_key(&crt, &dtls_srtp->pkey);

  mbedtls_x509write_crt_set_subject_name(&crt, "CN=dtls_srtp");

  mbedtls_x509write_crt_set_issuer_name(&crt, "CN=dtls_srtp");

  mbedtls_x509write_crt_set_validity(&crt, "20180101000000", "20280101000000");

  ret = mbedtls_x509write_crt_pem(&crt, cert_buf, CERT_BUF_SIZE, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

  if (ret < 0) {

    printf("mbedtls_x509write_crt_pem failed\n");
    return -1;
  }

  mbedtls_x509_crt_parse(&dtls_srtp->cert, cert_buf, CERT_BUF_SIZE);

  mbedtls_x509write_crt_free(&crt);

  return 0;

}

int dtls_srtp_init(DtlsSrtp *dtls_srtp, UdpSocket *udp_socket, DtlsSrtpRole role) {

  static const mbedtls_ssl_srtp_profile default_profiles[] = {
   MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80,
   MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32,
   MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80,
   MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32,
   MBEDTLS_TLS_SRTP_UNSET
  };

  dtls_srtp->role = role;
  dtls_srtp->udp_socket = udp_socket;
  dtls_srtp->udp_send = dtls_srtp_udp_send;
  dtls_srtp->udp_recv = dtls_srtp_udp_recv;

  mbedtls_ssl_config_init(&dtls_srtp->conf);
  mbedtls_ssl_init(&dtls_srtp->ssl);

  mbedtls_x509_crt_init(&dtls_srtp->cert);
  mbedtls_pk_init(&dtls_srtp->pkey);
  mbedtls_entropy_init(&dtls_srtp->entropy);
  mbedtls_ctr_drbg_init(&dtls_srtp->ctr_drbg);

  dtls_srtp_selfsign_cert(dtls_srtp);

  mbedtls_ssl_conf_verify(&dtls_srtp->conf, dtls_srtp_cert_verify, NULL);

  mbedtls_ssl_conf_authmode(&dtls_srtp->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

  mbedtls_ssl_conf_ca_chain(&dtls_srtp->conf, &dtls_srtp->cert, NULL);

  mbedtls_ssl_conf_own_cert(&dtls_srtp->conf, &dtls_srtp->cert, &dtls_srtp->pkey);

  mbedtls_ssl_conf_rng(&dtls_srtp->conf, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

  mbedtls_ssl_conf_read_timeout(&dtls_srtp->conf, 1000);

  if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {

    mbedtls_ssl_config_defaults(&dtls_srtp->conf,
     MBEDTLS_SSL_IS_SERVER,
     MBEDTLS_SSL_TRANSPORT_DATAGRAM,
     MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_cookie_init(&dtls_srtp->cookie_ctx);

    mbedtls_ssl_cookie_setup(&dtls_srtp->cookie_ctx, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

    mbedtls_ssl_conf_dtls_cookies(&dtls_srtp->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &dtls_srtp->cookie_ctx);

  } else {

    mbedtls_ssl_config_defaults(&dtls_srtp->conf,
     MBEDTLS_SSL_IS_CLIENT,
     MBEDTLS_SSL_TRANSPORT_DATAGRAM,
     MBEDTLS_SSL_PRESET_DEFAULT);
  }

  dtls_srtp_x509_digest(&dtls_srtp->cert, dtls_srtp->local_fingerprint);

  LOGD("local fingerprint: %s", dtls_srtp->local_fingerprint);

  mbedtls_ssl_conf_dtls_srtp_protection_profiles(&dtls_srtp->conf, default_profiles);

  mbedtls_ssl_conf_srtp_mki_value_supported(&dtls_srtp->conf, MBEDTLS_SSL_DTLS_SRTP_MKI_UNSUPPORTED);

  mbedtls_ssl_setup(&dtls_srtp->ssl, &dtls_srtp->conf);

  if(srtp_init() != srtp_err_status_ok) {

    LOGE("libsrtp init failed");
  }

  return 0;
}

static void dtls_srtp_key_derivation(void *context, mbedtls_ssl_key_export_type secret_type,
 const unsigned char *secret, size_t secret_len,
 const unsigned char client_random[32],
 const unsigned char server_random[32],
 mbedtls_tls_prf_types tls_prf_type) {

  DtlsSrtp *dtls_srtp = (DtlsSrtp *) context;

  int ret;

  const char *dtls_srtp_label = "EXTRACTOR-dtls_srtp";

  char randbytes[64];

  uint8_t key_material[DTLS_SRTP_KEY_MATERIAL_LENGTH];

  memcpy(randbytes, client_random, 32);
  memcpy(randbytes + 32, server_random, 32);

  // Export keying material
  if ((ret = mbedtls_ssl_tls_prf(tls_prf_type, secret, secret_len, dtls_srtp_label,
   randbytes, sizeof(randbytes), key_material, sizeof(key_material))) != 0) {
    
    LOGE("mbedtls_ssl_tls_prf failed(%d)", ret);
    return;
  }

#if 0
  int i, j;
  printf("    DTLS-SRTP key material is:");
  for (j = 0; j < sizeof(key_material); j++) {
    if (j % 8 == 0) {
      printf("\n    ");
    }
    printf("%02x ", key_material[j]);
  }
  printf("\n");

  /* produce a less readable output used to perform automatic checks
   * - compare client and server output
   * - interop test with openssl which client produces this kind of output
   */
  printf("    Keying material: ");
  for (j = 0; j < sizeof(key_material); j++) {
    printf("%02X", key_material[j]);
  }
  printf("\n");
#endif

  // derive inbounds keys

  memset(&dtls_srtp->remote_policy, 0, sizeof(dtls_srtp->remote_policy));

  srtp_crypto_policy_set_rtp_default(&dtls_srtp->remote_policy.rtp); 
  srtp_crypto_policy_set_rtcp_default(&dtls_srtp->remote_policy.rtcp);

  memcpy(dtls_srtp->remote_policy_key, key_material, SRTP_MASTER_KEY_LENGTH);
  memcpy(dtls_srtp->remote_policy_key + SRTP_MASTER_KEY_LENGTH, key_material + SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_KEY_LENGTH, SRTP_MASTER_SALT_LENGTH);

  dtls_srtp->remote_policy.ssrc.type = ssrc_any_inbound;
  dtls_srtp->remote_policy.key = dtls_srtp->remote_policy_key;
  dtls_srtp->remote_policy.next = NULL;

  if (srtp_create(&dtls_srtp->srtp_in, &dtls_srtp->remote_policy) != srtp_err_status_ok) {

    LOGD("Error creating inbound SRTP session for component");
    return;
  }

  LOGI("Created inbound SRTP session");

  // derive outbounds keys
  memset(&dtls_srtp->local_policy, 0, sizeof(dtls_srtp->local_policy));

  srtp_crypto_policy_set_rtp_default(&dtls_srtp->local_policy.rtp);
  srtp_crypto_policy_set_rtcp_default(&dtls_srtp->local_policy.rtcp);

  memcpy(dtls_srtp->local_policy_key, key_material + SRTP_MASTER_KEY_LENGTH, SRTP_MASTER_KEY_LENGTH);
  memcpy(dtls_srtp->local_policy_key + SRTP_MASTER_KEY_LENGTH, key_material + SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH, SRTP_MASTER_SALT_LENGTH);

  dtls_srtp->local_policy.ssrc.type = ssrc_any_outbound;
  dtls_srtp->local_policy.key = dtls_srtp->local_policy_key;
  dtls_srtp->local_policy.next = NULL;

  if (srtp_create(&dtls_srtp->srtp_out, &dtls_srtp->local_policy) != srtp_err_status_ok) {

    LOGE("Error creating outbound SRTP session");
    return;
  }

  LOGI("Created outbound SRTP session");
}

static int dtls_srtp_do_handshake(DtlsSrtp *dtls_srtp) {

  int ret;
  
  static mbedtls_timing_delay_context timer; 

  mbedtls_ssl_set_timer_cb(&dtls_srtp->ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

  mbedtls_ssl_set_export_keys_cb(&dtls_srtp->ssl, dtls_srtp_key_derivation, dtls_srtp);

  mbedtls_ssl_set_bio(&dtls_srtp->ssl, dtls_srtp, dtls_srtp_udp_send, dtls_srtp_udp_recv, NULL);
  
  do {

    ret = mbedtls_ssl_handshake(&dtls_srtp->ssl);

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  return ret;
}

static int dtls_srtp_handshake_server(DtlsSrtp *dtls_srtp) {

  int ret;

  while (1) {

    unsigned char client_ip[] = "test";

    mbedtls_ssl_session_reset(&dtls_srtp->ssl);

    mbedtls_ssl_set_client_transport_id(&dtls_srtp->ssl, client_ip, sizeof(client_ip)); 

    ret = dtls_srtp_do_handshake(dtls_srtp);

    if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {

      LOGD("DTLS hello verification requested");

    } else if (ret != 0) {

      LOGD("failed! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int) -ret);

      break;

    } else {

      break;
    }
  }

  LOGD("DTLS server handshake done");

  return ret;
}

static int dtls_srtp_handshake_client(DtlsSrtp *dtls_srtp) {

  int ret;

  ret = dtls_srtp_do_handshake(dtls_srtp);

  if (ret != 0) {

    LOGD("failed! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int) -ret);
  }

  int flags;

  if ((flags = mbedtls_ssl_get_verify_result(&dtls_srtp->ssl)) != 0) {
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    char vrfy_buf[512];
#endif

    printf(" failed\n");

#if !defined(MBEDTLS_X509_REMOVE_INFO)
    mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

    printf("%s\n", vrfy_buf);
#endif
  }

  LOGD("DTLS client handshake done");

  return ret;
}


int dtls_srtp_handshake(DtlsSrtp *dtls_srtp, Address *addr) {

  int ret;

  const mbedtls_x509_crt *remote_crt;

  dtls_srtp->remote_addr = addr;

  if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {

    ret = dtls_srtp_handshake_server(dtls_srtp);

  } else {

    ret = dtls_srtp_handshake_client(dtls_srtp);

  }

  if ((remote_crt = mbedtls_ssl_get_peer_cert(&dtls_srtp->ssl)) != NULL) {

    dtls_srtp_x509_digest(remote_crt, dtls_srtp->remote_fingerprint);

    LOGD("remote fingerprint: %s", dtls_srtp->remote_fingerprint);

  } else {

    LOGE("no remote fingerprint");

  }

  mbedtls_dtls_srtp_info dtls_srtp_negotiation_result;
  mbedtls_ssl_get_dtls_srtp_negotiation_result(&dtls_srtp->ssl, &dtls_srtp_negotiation_result);

  return ret;
}

int dtls_srtp_write(DtlsSrtp *dtls_srtp, const unsigned char *buf, size_t len) {

  int ret;

  do {

    ret = mbedtls_ssl_write(&dtls_srtp->ssl, buf, len);

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  return ret;
}

int dtls_srtp_read(DtlsSrtp *dtls_srtp, unsigned char *buf, size_t len) {

  int ret;

  memset(buf, 0, len);

  do {

    ret = mbedtls_ssl_read(&dtls_srtp->ssl, buf, len);

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  return ret;
}

