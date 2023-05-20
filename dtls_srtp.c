#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test/certs.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"

#include "dtls_srtp.h"
#include "address.h"
#include "udp.h"
#include "utils.h"

int dtls_srtp_udp_send(void *ctx, const unsigned char *buf, size_t len) {

  DtlsSrtp *dtls_srtp = (DtlsSrtp *) ctx;

  int ret = udp_socket_sendto(dtls_srtp->udp_socket, dtls_srtp->remote_addr, buf, len);

  LOGD("dtls_srtp_udp_send (%d)", ret);

  return ret;
}


int dtls_srtp_udp_recv(void *ctx, unsigned char *buf, size_t len) {

  DtlsSrtp *dtls_srtp = (DtlsSrtp *) ctx;

  int ret = udp_socket_recvfrom(dtls_srtp->udp_socket, &dtls_srtp->udp_socket->bind_addr, buf, len);

  LOGD("dtls_srtp_udp_recv (%d)", ret);

  return ret;

}

int dtls_srtp_init(DtlsSrtp *dtls_srtp, UdpSocket *udp_socket, DtlsSrtpRole role) {

  dtls_srtp->role = role;
  dtls_srtp->udp_socket = udp_socket;

  mbedtls_ssl_config_init(&dtls_srtp->conf);
  mbedtls_ssl_init(&dtls_srtp->ssl);
  mbedtls_ssl_cookie_init(&dtls_srtp->cookie_ctx);

  mbedtls_x509_crt_init(&dtls_srtp->cert);
  mbedtls_pk_init(&dtls_srtp->pkey);
  mbedtls_entropy_init(&dtls_srtp->entropy);
  mbedtls_ctr_drbg_init(&dtls_srtp->ctr_drbg);
  
  dtls_srtp->udp_send = dtls_srtp_udp_send;
  dtls_srtp->udp_recv = dtls_srtp_udp_recv;

  return 0;
}

int dtls_srtp_create_cert(DtlsSrtp *dtls_srtp) {

  const char *pers = "dtls_srtp";

  mbedtls_ctr_drbg_seed(&dtls_srtp->ctr_drbg, mbedtls_entropy_func, &dtls_srtp->entropy, (const unsigned char *) pers, strlen(pers));

  if (mbedtls_pk_setup(&dtls_srtp->pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
    printf("mbedtls_pk_setup failed\n");
    return -1;
  }

  if (mbedtls_rsa_gen_key(mbedtls_pk_rsa(dtls_srtp->pkey), mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg, 2048, 65537) != 0) {
    printf("mbedtls_rsa_gen_key failed\n");
    return -1;
  }

  mbedtls_x509write_cert crt;

  mbedtls_x509write_crt_init(&crt);

  mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

  mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

  mbedtls_x509write_crt_set_subject_key(&crt, &dtls_srtp->pkey);

  mbedtls_x509write_crt_set_issuer_key(&crt, &dtls_srtp->pkey);

  mbedtls_x509write_crt_set_subject_name(&crt, "CN=dtls_srtp");

  mbedtls_x509write_crt_set_issuer_name(&crt, "CN=dtls_srtp");

  mbedtls_x509write_crt_set_validity(&crt, "20180101000000", "20280101000000");

  mbedtls_x509write_crt_set_basic_constraints(&crt, 0, 0);

  mbedtls_x509write_crt_set_subject_key_identifier(&crt);

  mbedtls_x509write_crt_set_authority_key_identifier(&crt);
  
}

static int dtls_srtp_do_handshake(DtlsSrtp *dtls_srtp) {

  int ret;
  
  static mbedtls_timing_delay_context timer; 

  mbedtls_ssl_set_timer_cb(&dtls_srtp->ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

  mbedtls_ssl_set_bio(&dtls_srtp->ssl, dtls_srtp, dtls_srtp_udp_send, dtls_srtp_udp_recv, NULL);
  
  do {

    ret = mbedtls_ssl_handshake(&dtls_srtp->ssl);

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  return ret;
}

static int dtls_srtp_handshake_server(DtlsSrtp *dtls_srtp) {

  int ret;

  const char *pers = "dtls_server"; 

  mbedtls_ctr_drbg_seed(&dtls_srtp->ctr_drbg, mbedtls_entropy_func, &dtls_srtp->entropy, (const unsigned char *) pers, strlen(pers));

  mbedtls_x509_crt_parse(&dtls_srtp->cert, (const unsigned char *) mbedtls_test_srv_crt, mbedtls_test_srv_crt_len);

  mbedtls_x509_crt_parse(&dtls_srtp->cert, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len);

  mbedtls_pk_parse_key(&dtls_srtp->pkey, (const unsigned char *) mbedtls_test_srv_key, mbedtls_test_srv_key_len, NULL, 0, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

  mbedtls_ssl_config_defaults(&dtls_srtp->conf,
   MBEDTLS_SSL_IS_SERVER,
   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
   MBEDTLS_SSL_PRESET_DEFAULT);

  mbedtls_ssl_conf_ca_chain(&dtls_srtp->conf, dtls_srtp->cert.next, NULL);

  mbedtls_ssl_conf_own_cert(&dtls_srtp->conf, &dtls_srtp->cert, &dtls_srtp->pkey);

  mbedtls_ssl_cookie_setup(&dtls_srtp->cookie_ctx, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

  mbedtls_ssl_conf_dtls_cookies(&dtls_srtp->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &dtls_srtp->cookie_ctx);

  mbedtls_ssl_conf_rng(&dtls_srtp->conf, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

  mbedtls_ssl_conf_read_timeout(&dtls_srtp->conf, 1000);

  mbedtls_ssl_setup(&dtls_srtp->ssl, &dtls_srtp->conf);

  while (1) {

    unsigned char client_ip[] = "test";

    size_t cliip_len;

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

  const char *pers = "dtls_client";

  mbedtls_timing_delay_context timer; 

  mbedtls_ctr_drbg_seed(&dtls_srtp->ctr_drbg, mbedtls_entropy_func, &dtls_srtp->entropy, (const unsigned char *) pers, strlen(pers));

  mbedtls_x509_crt_parse(&dtls_srtp->cert, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len);

  mbedtls_ssl_config_defaults(&dtls_srtp->conf,
   MBEDTLS_SSL_IS_CLIENT,
   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
   MBEDTLS_SSL_PRESET_DEFAULT);

  mbedtls_ssl_conf_authmode(&dtls_srtp->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&dtls_srtp->conf, &dtls_srtp->cert, NULL);
  mbedtls_ssl_conf_rng(&dtls_srtp->conf, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);
  mbedtls_ssl_conf_read_timeout(&dtls_srtp->conf, 1000);

  mbedtls_ssl_setup(&dtls_srtp->ssl, &dtls_srtp->conf);

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

  dtls_srtp->remote_addr = addr;

  if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {

    return dtls_srtp_handshake_server(dtls_srtp);

  } else {

    return dtls_srtp_handshake_client(dtls_srtp);

  }
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


