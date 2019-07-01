#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/base64.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "soc/efuse_reg.h"
#include "esp_ota_ops.h"
#include "esp_log.h"

#include "http_parser.h"

#include "vfs.h"
#include "ota.h"
#include "ota_config.h"

#define BASE64LEN(x)	(((x) + 3 - 1) / 3)

#define OTA_ERROR_PRINTF(format, ... )	ESP_LOGI("OTA", format, ##__VA_ARGS__)

uint64_t otaGetChipID(void);
bool readFileToBuff(char *filename, char **buff, size_t *len);


static QueueHandle_t otaControlQueue;

uint64_t otaGetChipID(void){
	uint64_t word16 = REG_READ(EFUSE_BLK0_RDATA1_REG);
	uint64_t word17 = REG_READ(EFUSE_BLK0_RDATA2_REG);
	const uint64_t MAX_UINT24 = 0xffffff;
	
	return ((word17 & MAX_UINT24) << 24) | ((word16 >> 8) & MAX_UINT24);
}

bool readFileToBuff(char *filename, char **buff, size_t *len)
{
	int fileFd = 0;
	bool retval = false;
	
	size_t size;
	
	if(len != NULL)
	{
		*len = 0;
	}
	
	if((filename != NULL) && (buff != NULL))
	{
		fileFd = vfs_open(filename, "r");
		if(fileFd > 0)
		{	
			vfs_lseek(fileFd, 0L, VFS_SEEK_END);
			size = vfs_tell(fileFd) + 1;
			vfs_lseek(fileFd, 0L, VFS_SEEK_SET);
			*buff = (char *) calloc(size, sizeof(char));
			if(*buff != NULL)
			{
				memset(*buff, 0, size);
				if((size = vfs_read(fileFd, *buff, size)) > 0)
				{	
					retval = true;
					if(len != NULL)
					{
						*len = size;
					}
				}
				else
				{
					free(*buff);
					*buff = NULL;
				}
			}
			vfs_close(fileFd);
		}
	}

	return retval;
}

bool writeBuffToFile(char *filename, uint8_t *buff, size_t len)
{
	int fileFd = 0;
	bool retval = false;
	
	if((buff != NULL) && (len > 0))
	{
		fileFd = vfs_open(filename, "w");
		if(fileFd > 0)
		{
			if(vfs_write(fileFd, buff, len) == len)
			{
				retval = true;
			}
			else
			{
				//could not write all data
			}
			vfs_close(fileFd);
		}
		else
		{
			//could not create/open file
		}
	}
	return retval;
}

bool otaClientInit(otaSSLTransportType **ssl)
{
	int ret;
	bool retval = false;
	
	if(ssl != NULL)
	{
		*ssl = (otaSSLTransportType *)calloc(1, sizeof(otaSSLTransportType));
		if(*ssl != NULL)
		{
			mbedtls_ssl_init(&(*ssl)->ctx);
			mbedtls_ctr_drbg_init(&(*ssl)->ctr_drbg);
			mbedtls_ssl_config_init(&(*ssl)->conf);
			mbedtls_entropy_init(&(*ssl)->entropy);
			mbedtls_net_init(&(*ssl)->client_fd);
			if ((ret = mbedtls_ssl_config_defaults(&(*ssl)->conf,
													   MBEDTLS_SSL_IS_CLIENT,
													   MBEDTLS_SSL_TRANSPORT_STREAM,
													   MBEDTLS_SSL_PRESET_DEFAULT)) == 0) 
			{
				if ((ret = mbedtls_ctr_drbg_seed(&(*ssl)->ctr_drbg, mbedtls_entropy_func, &(*ssl)->entropy, NULL, 0)) == 0) 
				{
					mbedtls_ssl_conf_rng(&(*ssl)->conf, mbedtls_ctr_drbg_random, &(*ssl)->ctr_drbg);
					retval = true;
				}
				else
				{
					mbedtls_strerror(ret, (*ssl)->errorString, sizeof((*ssl)->errorString) / sizeof((*ssl)->errorString[0]));
					OTA_ERROR_PRINTF("mbedtls_ctr_drbg_seed returned %s", (*ssl)->errorString );
				}
			}
			else
			{
				mbedtls_strerror(ret, (*ssl)->errorString, sizeof((*ssl)->errorString) / sizeof((*ssl)->errorString[0]));
				OTA_ERROR_PRINTF("mbedtls_ssl_config_defaults returned %s", (*ssl)->errorString );
			}			
		}
		else
		{
			*ssl = NULL;
		}
		
	}
	return retval;
}

bool otaClientReadCA(otaSSLTransportType *ssl, char *caCert)
{
	char *pemData = NULL;
	size_t len = 0;
	bool retval = false;
	int ret = 0;
	
	if(ssl != NULL)
	{
		ssl->errorString[0] = '\0';
		if(ssl->cacert != NULL)
		{
			if(readFileToBuff(caCert, &pemData, &len))
			{	
				if((ssl->cacert = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt))) != NULL)
				{
					mbedtls_x509_crt_init(ssl->cacert);
					if ((ret = mbedtls_x509_crt_parse(ssl->cacert, (uint8_t *)pemData, len + 1)) >= 0) 
					{
						retval = true;
					}
					else
					{
						free(ssl->cacert);
						mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
						OTA_ERROR_PRINTF("mbedtls_x509_crt_parse returned %s", ssl->errorString);
					}
				}
				else
				{
					OTA_ERROR_PRINTF("Could not allocate memory for cacert");
				}
				free(pemData);
			}
			else
			{
				OTA_ERROR_PRINTF("Could not read CA file %s", caCert);
			}
		}
	}

	return retval;
}

bool otaClientReadCL(otaSSLTransportType *ssl, char *clCert, char *clKey)
{
	char *pemData = NULL;
	size_t len = 0;
	bool retval = false;
	int ret = 0;
	
	if(ssl != NULL)
	{
		ssl->errorString[0] = '\0';
		if((ssl->clcert != NULL) && (ssl->clkey != NULL))
		{
			if(readFileToBuff(clKey, &pemData, &len))
			{
				if((ssl->clkey = (mbedtls_pk_context *)malloc(sizeof(mbedtls_pk_context))) != NULL)
				{
					mbedtls_pk_init( ssl->clkey );
					if((ret = mbedtls_pk_parse_key(ssl->clkey, (uint8_t *)pemData, len +1, NULL, 0)) >= 0)
					{
						free(pemData);
						pemData = 0;
						if(readFileToBuff(clCert, &pemData, &len))
						{
							if((ssl->clcert = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt))) != NULL)
							{
								mbedtls_x509_crt_init(ssl->clcert);
								if ((ret = mbedtls_x509_crt_parse(ssl->clcert, (uint8_t *)pemData, len + 1)) < 0) 
								{
									retval = true;
								}
								else
								{
									free(ssl->clkey);
									ssl->clkey = NULL;
									free(ssl->clcert);
									ssl->clcert = NULL;
									mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
									OTA_ERROR_PRINTF("mbedtls_x509_crt_parse returned %s", ssl->errorString);
								}
							}
							else
							{
								OTA_ERROR_PRINTF("Could not allocate memory for clcert");
							}
						}
						else
						{
							OTA_ERROR_PRINTF("Could not read client Cert file %s", clCert);
						}
					}
					else
					{
						free(ssl->clkey);
						ssl->clkey = NULL;
						mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
						OTA_ERROR_PRINTF("mbedtls_pk_parse_key returned %s", ssl->errorString);
					}
				}
				else
				{
					OTA_ERROR_PRINTF("Could not allocate memory for clkey");
				}
				free(pemData);
			}
			else
			{
				OTA_ERROR_PRINTF("Could not read Key file %s", clKey);
			}
		}
	}
	return retval;	
}

void otaClientDenit(otaSSLTransportType *ssl)
{
	if(ssl != NULL)
	{
		mbedtls_net_free( &ssl->client_fd );

		if(ssl->cacert != NULL)
			mbedtls_x509_crt_free( ssl->cacert );
		if(ssl->clcert != NULL)
			mbedtls_x509_crt_free( ssl->clcert );
		if(ssl->clkey != NULL)
			mbedtls_pk_free( ssl->clkey );

		mbedtls_ssl_free( &ssl->ctx );
		mbedtls_ssl_config_free( &ssl->conf );
		mbedtls_ctr_drbg_free( &ssl->ctr_drbg );
		mbedtls_entropy_free( &ssl->entropy );
		
		free(ssl);
		ssl = NULL;
	}
}

bool otaClientWrite(otaSSLTransportType *ssl, char *buff, size_t len)
{
	size_t bytesSent = 0;
	int ret;
	
	if((ssl != NULL) && (buff != NULL) && (len > 0))
	{
		do
		{
			ret = mbedtls_ssl_write(&ssl->ctx, (uint8_t *)(buff + bytesSent), len - bytesSent);
			
			if((ret < 0))
			{
				if((ret == MBEDTLS_ERR_SSL_WANT_READ) || (ret == MBEDTLS_ERR_SSL_WANT_WRITE))
				{
					vTaskDelay(10);
				}
				else
				{
					mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
					OTA_ERROR_PRINTF("mbedtls_pk_parse_key returned %s", ssl->errorString);
					break;
				}
			}
			else
			{
				bytesSent += ret;
			}
		}while(len != bytesSent);
	}
	return bytesSent == len;
}

bool httpsClientConnect(otaSSLTransportType *ssl, char *hostname, char *port)
{
	bool retval = false;
	int ret;
	uint32_t flags;
	
	if((ssl != NULL) && (hostname != NULL) && (port != NULL))
	{
		ssl->errorString[0] = '\0';
		ret = 0;
		if (ssl->cacert) 
		{
			mbedtls_ssl_conf_ca_chain(&ssl->conf, ssl->cacert, NULL);
			if ((ssl->clcert) && (ssl->clkey))
			{
				ret = mbedtls_ssl_conf_own_cert(&ssl->conf, ssl->clcert, ssl->clkey);
			}
			mbedtls_ssl_conf_authmode(&ssl->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		}
		else
		{
			mbedtls_ssl_conf_authmode(&ssl->conf, MBEDTLS_SSL_VERIFY_NONE);
		}
		
		if(ret == 0)
		{						
			if ((ret = mbedtls_ssl_setup(&ssl->ctx, &ssl->conf)) == 0) 
			{
				//setsockopt(ssl->client_fd.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
				if ((ret = mbedtls_net_connect(&ssl->client_fd, hostname, port, MBEDTLS_NET_PROTO_TCP)) == 0) 
				{
					mbedtls_ssl_set_bio(&ssl->ctx, &ssl->client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
					if((ret = mbedtls_ssl_set_hostname(&ssl->ctx, hostname)) == 0) 
					{
						while ((ret = mbedtls_ssl_handshake(&ssl->ctx)) != 0) 
						{
							if ((ret == MBEDTLS_ERR_SSL_WANT_READ) || (ret == MBEDTLS_ERR_SSL_WANT_WRITE)) 
							{
								vTaskDelay(1);
							}
						}
						
						if(ret == 0)
						{
							if ((flags = mbedtls_ssl_get_verify_result(&ssl->ctx)) == 0) 
							{
								retval = true;
							} 
							else 
							{
								OTA_ERROR_PRINTF("mbedtls_ssl_get_verify_result returned %u", flags );
							}
						}
						else
						{
							mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
							OTA_ERROR_PRINTF("mbedtls_ssl_handshake returned %s", ssl->errorString );
						}
					}
					else
					{
						mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
						OTA_ERROR_PRINTF("mbedtls_net_connect returned %s", ssl->errorString );
					}
				}
				else
				{
					mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
					OTA_ERROR_PRINTF("mbedtls_net_connect returned %s", ssl->errorString );
				}
			}
			else
			{
				mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
				OTA_ERROR_PRINTF("mbedtls_ssl_setup returned %s", ssl->errorString );
			}
		}
		else
		{
			mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
			OTA_ERROR_PRINTF("mbedtls_ssl_conf_own_cert returned %s", ssl->errorString );
		}
	}
	return retval;
}

bool otaGeneratePK(otaSSLTransportType *ssl, char *pkName, uint16_t keySize, char *curveName) 
{
	int ret;
	bool retval = false;
	uint8_t *buff;
	int fileFd = 0;
	
	mbedtls_pk_type_t pktype = MBEDTLS_PK_RSA;	
	mbedtls_pk_context pk;
	
	#if defined(MBEDTLS_ECP_C)
		mbedtls_ecp_curve_info *curve_info = NULL;
	#endif
	
	mbedtls_pk_init( &pk );
	
	if(ssl != NULL)
	{
		ssl->errorString[0] = '\0';
	#if defined(MBEDTLS_ECP_C)
		if(curveName != NULL)
		{
			curve_info = mbedtls_ecp_curve_info_from_name( curveName );
			pktype = MBEDTLS_PK_ECKEY;
		}
	#elif
		if(curveName == NULL)
		{
			 OTA_ERROR_PRINTF("ECC not supported");
		}
	#endif
	
		if((ret = mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type( pktype ) )) == 0)
		{
			ret = 1;
			#if defined(MBEDTLS_ECP_C)
				if(curve_info != NULL)
				{
					ret = mbedtls_ecp_gen_key( curve_info->grp_id, mbedtls_pk_ec( pk ), mbedtls_ctr_drbg_random, &ssl->ctr_drbg );
				}
				else
			#endif
			#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
				{
					ret = mbedtls_rsa_gen_key( mbedtls_pk_rsa( pk ), mbedtls_ctr_drbg_random, &ssl->ctr_drbg, keySize, 65537 );
				}
			#endif
			if(ret == 0)
			{
				fileFd = vfs_open(pkName, "w");
				if(fileFd >  0)
				{
					buff = (uint8_t *)calloc(OTA_PEM_MAX_SIZE, sizeof(uint8_t));
					if(buff != NULL)
					{
						ret = mbedtls_pk_write_key_pem(&pk, buff, OTA_PEM_MAX_SIZE);
						if(ret == 0)
						{
							if(vfs_write(fileFd, buff, strlen((char *)buff)) == strlen((char *)buff))
							{
								retval = true;
							}
						}
						else
						{
							mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
							OTA_ERROR_PRINTF("mbedtls_pk_write_key_pem returned %s", ssl->errorString);
						}
						free(buff);
					}
					else
					{
						OTA_ERROR_PRINTF("Could not allocate memory for PEM buffer");
					}
					vfs_close(fileFd);
				}
			}
			else
			{
				mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
				OTA_ERROR_PRINTF("key generation fuction returned %s", ssl->errorString);
			}
				
		}
		else
		{
			mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
			OTA_ERROR_PRINTF("mbedtls_pk_setup returned %s", ssl->errorString);
		}
	}
	
	mbedtls_pk_free( &pk );
	return retval;
}

char *otaGenerateCSR(otaSSLTransportType *ssl, char *pkName, char *csrSubject){
	int ret;
	char csrSubjectBuff[50];
	
	char *pemData = NULL;
	size_t len = 0;
	
	mbedtls_pk_context key;
	mbedtls_x509write_csr req;

	if(ssl != NULL)
	{
		mbedtls_x509write_csr_init( &req );
		mbedtls_pk_init( &key );
		
		mbedtls_x509write_csr_set_md_alg( &req, MBEDTLS_MD_SHA256 );
		mbedtls_x509write_csr_set_key_usage( &req,  	MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
														MBEDTLS_X509_KU_KEY_ENCIPHERMENT |
														MBEDTLS_X509_KU_DATA_ENCIPHERMENT);
		mbedtls_x509write_csr_set_ns_cert_type( &req, 	MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT |
														MBEDTLS_X509_NS_CERT_TYPE_EMAIL);
														
		if(csrSubject != NULL)
		{
			strcpy(csrSubjectBuff, csrSubject);
		}
		else
		{
			sprintf(csrSubjectBuff, "CN=%llX,O=%s,C=%s", otaGetChipID(), OTA_DEFAULT_ORG, OTA_DEFAULT_CNTRY);
		}
														
		if( ( ret = mbedtls_x509write_csr_set_subject_name( &req, csrSubjectBuff ) ) == 0 )
		{
			if(readFileToBuff(pkName, &pemData, &len))
			{
				if( (ret = mbedtls_pk_parse_key( &key, (uint8_t *)pemData, len + 1, NULL, 0 )) == 0 )
				{
					mbedtls_x509write_csr_set_key( &req, &key );
					free(pemData);
					pemData = NULL;
					pemData = (char *)calloc(OTA_PEM_MAX_SIZE, sizeof(uint8_t));
					if(pemData != NULL)
					{
						if((ret = mbedtls_x509write_csr_pem(&req, (uint8_t *)pemData, OTA_PEM_MAX_SIZE,  mbedtls_ctr_drbg_random, &ssl->ctr_drbg)) == 0)
						{
							
						}
						else
						{
							free(pemData);
							pemData = NULL;
							mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
							OTA_ERROR_PRINTF("mbedtls_x509write_csr_pem returned %s", ssl->errorString );
						}
					}
					else
					{
						OTA_ERROR_PRINTF("could not allocate memory for pemData");
					}
				}
				else
				{
					free(pemData);
					pemData = NULL;
					mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
					OTA_ERROR_PRINTF("mbedtls_pk_parse_key returned %s", ssl->errorString );
				}
			}
			else
			{
				OTA_ERROR_PRINTF("could not read file %s", pkName);
			}
		}
		else
		{
			mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
			OTA_ERROR_PRINTF("mbedtls_x509write_csr_set_subject_name returned %s", ssl->errorString );
		}
		
		mbedtls_x509write_csr_free( &req );
		mbedtls_pk_free( &key );
	}
	
	return pemData;
}

bool otaRegister(otaMsgFirstTime *options){
	bool retval = false;
	
	char *csrPemData = NULL;
	char *httpHeader = NULL;
	char *httpBody = NULL;
	char httpBodyEnd[30];
	
	char baundry[] = "ab1234567cd";
	char unencodedAuth[42];
	unsigned char encodedString[BASE64LEN(sizeof(unencodedAuth))+1];
	char authHttpString[sizeof(encodedString)+21+2+1];
	
	char port[6];
	char hostname[31];
	char deviceName[] = {};
	char agent[] = {};
	
	struct http_parser_url purl;
	
	struct vfs_stat fstat;
	
	int httpBodySize = 0;
	int ret;
	size_t authEncSize;
	
	otaSSLTransportType *ssl;
	
	if(options != NULL)
	{
		if(otaClientInit(&ssl))
		{	
			vfs_remove(OTA_CRT_NAME);
			vfs_remove(OTA_CA_CERT_NAME);
			if(options->regenKey)
			{
				vfs_remove(OTA_KEY_NAME);
			}
			
			if(!vfs_stat(OTA_KEY_NAME, &fstat) == VFS_RES_OK)
			{
				otaGeneratePK(ssl, OTA_KEY_NAME, options->keySize > 0 ? options->keySize : OTA_DEFAULT_KEY_SIZE, 
								sizeof(options->curveName) > 0 ? options->curveName : NULL);
			}
				
			if((csrPemData = otaGenerateCSR(ssl, OTA_KEY_NAME, NULL)) != NULL)
			{
				if(strlen(options->username) > 0)
				{
					sprintf(unencodedAuth, "%s:%s", options->username, options->password);
					if((ret = mbedtls_base64_encode(encodedString, sizeof(encodedString), &authEncSize, (unsigned char *)unencodedAuth, strlen(unencodedAuth))) != 0)
					{
						sprintf(authHttpString, "Authorization: Basic %s\r\n", encodedString);
					}
					else
					{
						authHttpString[0] = '\0';
						mbedtls_strerror(ret, ssl->errorString, sizeof(ssl->errorString) / sizeof(ssl->errorString[0]));
						OTA_ERROR_PRINTF("mbedtls_base64_encode returned %s", ssl->errorString );
					}
				}
				
				ret = asprintf(&httpBody,	"--%s\r\n"
											"Content-Disposition: form-data; name=\"id\"\r\n\r\n"
											"%llX\r\n"
											"--%s\r\n"
											"Content-Disposition: form-data; name=\"device\"\r\n\r\n"
											"%s\r\n"
											"--%s\r\n"
											"Content-Disposition: form-data; name=\"csr\"; filename=\"otaCL.csr\"\r\n"
											"Content-Type: text/plain\r\n\r\n",
											baundry, otaGetChipID(), baundry, deviceName, baundry);
				sprintf(httpBodyEnd, "\r\n--%s--\r\n", baundry);
											
				if(ret > 0)
				{ 
					httpBodySize = ret;
					httpBodySize += strlen(httpBodyEnd);
					httpBodySize += strlen(csrPemData);
					
					http_parser_url_init(&purl);
					if(http_parser_parse_url(options->serverURL, strlen(options->serverURL), 0, &purl) == 0)
					{
						sprintf(port, "%u",  purl.field_data[UF_PORT].len > 0 ? purl.port : 443);
						sprintf(hostname, "%.*s", purl.field_data[UF_HOST].len, options->serverURL + purl.field_data[UF_HOST].off);
						ret = asprintf(&httpHeader,"POST %s HTTP/1.1\r\n"
													"Host: %s\r\n"
													"User-Agent: %s\r\n"
													"Accept: text/plain\r\n"
													"Accept-Encoding: identity\r\n"
													"%s"
													"Connection: keep-alive\r\n"
													"Content-Type: multipart/form-data; boundary=%s\r\n"
													"Content-Length: %d\r\n\r\n", 
													purl.field_data[UF_PATH].len > 0 ? options->serverURL + purl.field_data[UF_PATH].off : "/", 
													hostname, 
													agent, authHttpString, baundry, httpBodySize);
						if(ret > 0)
						{
							if(httpsClientConnect(ssl, hostname, port))
							{
								if(otaClientWrite(ssl, httpHeader, sizeof(httpHeader)))
								{
									if(otaClientWrite(ssl, httpBody, sizeof(httpBody)))
									{
										if(otaClientWrite(ssl, csrPemData, sizeof(csrPemData)))
										{
											if(otaClientWrite(ssl, httpBodyEnd, sizeof(httpBodyEnd)))
											{
												retval = true;
											}
										}
									}
								}
							}
							free(httpHeader);
						}
					}
					else
					{
						OTA_ERROR_PRINTF("Error parse url %s", options->serverURL);
					}
					free(httpBody);
				}
				free(csrPemData);
			}
		}
		otaClientDenit(ssl);				
	}
	return retval;
}

void otaTask(void * pvParameters ){
	
	otaControlQueue = xQueueCreate(OTA_CTRL_QUEUE_SIZE, sizeof(otaMsgType));
	otaAutoUpdateStruct *autoUpdate = NULL;
	otaMsgType msg;
	
	time_t lastUpdateTime = 0;
	time_t currentTime = 0;
	struct tm *currentTimeInfo = NULL;
	
	bool runTask = true;
	
	otaSSLTransportType *ssl;
	
	ssl = (otaSSLTransportType *) malloc(sizeof(otaSSLTransportType));
	
	while(runTask)
	{
		if(xQueueReceive(otaControlQueue, &msg, 900000/portTICK_PERIOD_MS) == pdTRUE)
		{
			switch(msg.msg)
			{
				case OTA_MSG_FIRSTIME:
					otaRegister((otaMsgFirstTime *)msg.data);
					break;
				case OTA_MSG_DELETE_TASK:
					runTask = false;
					break;
				default:
					break;
			}
			if(msg.data != NULL)
			{
				free(msg.data);
			}
		}
		else
		{
			time(&currentTime);
			if((autoUpdate != NULL) && ((currentTime - lastUpdateTime) > 60))
			{
				currentTimeInfo = localtime(&currentTime);
				
				if(	(autoUpdate->dayOfMonth & (1 << (currentTimeInfo->tm_mday - 1))) &&
					(autoUpdate->dayOfWeek & (1 << currentTimeInfo->tm_wday)) &&
					(autoUpdate->hour == currentTimeInfo->tm_hour))
				{
					//invoke autoupdate
				}
			}
		}		
	}	
	
	if(autoUpdate != NULL)
	{
		free(autoUpdate);
	}
	otaClientDenit(ssl);
	vQueueDelete(otaControlQueue);
	otaControlQueue = NULL;
	vTaskDelete(NULL);
}