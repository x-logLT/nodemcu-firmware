#ifndef __OTA_H
#define __OTA_H



typedef struct {
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context      ctx;
    mbedtls_x509_crt         *cacert;
	mbedtls_x509_crt         *clcert;
	mbedtls_pk_context		 *clkey;
    mbedtls_ssl_config       conf;
    mbedtls_net_context      client_fd;
    bool                     ssl_initialized;
    bool                     verify_server;
	char					 errorString[100];
} otaSSLTransportType;

typedef struct {
	uint8_t dayOfWeek;
	uint32_t dayOfMonth;
	uint8_t hour;
}otaAutoUpdateStruct;

typedef enum {
	OTA_MSG_FIRSTIME,
	OTA_MSG_DELETE_TASK,
}otaMsgEum;

typedef struct {
	otaMsgEum msg;
	void * data;
}otaMsgType;

typedef struct {
	char serverURL[100];
	char curveName[48];
	char username[20];
	char password[20];
	uint16_t keySize;
	bool regenKey;
}otaMsgFirstTime;

#endif