#include "module.h"
#include "lauxlib.h"
#include "platform.h"

#include "vfs.h"
#include <string.h>

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

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "soc/efuse_reg.h"
#include "esp_ota_ops.h"

#include "ota.h"

#define OTA_READ_BUFF_SIZE	0x1000

/**
 *  mbedtls specific transport data
 */
 

typedef struct
{
	 esp_ota_handle_t ota;
}otaDataType;

static esp_ota_handle_t ota_handle = 0;

static int ota_genpk(lua_State *L) {	
	keyGenType *taskOptions = (keyGenType *) malloc(sizeof(keyGenType));
	TaskHandle_t xHandle = NULL;
	
	if(taskOptions != NULL){
		memset(taskOptions, 0, sizeof(keyGenType));
		strcpy(taskOptions->pkName, luaL_checklstring( L, 1, NULL ));
		taskOptions->keySize = luaL_checkint( L, 2 );
		taskOptions->curveName = NULL;//luaL_optlstring( L, 3, NULL, NULL ); 
		
		xTaskCreatePinnedToCore( generatePKTask, "generatePK", 8096, taskOptions, uxTaskPriorityGet(NULL), &xHandle, APP_CPU_NUM );

	}
	
	return 0;
}

static int ota_get_boot_partition(lua_State *L) {
	lua_pushlightuserdata(L, esp_ota_get_boot_partition()->address);
	return 1;
}

static int ota_get_running_partition(lua_State *L) {
	lua_pushlightuserdata(L, esp_ota_get_running_partition()->address);
	return 1;
}

static int ota_get_next_update_partition(lua_State *L) {
	lua_pushlightuserdata(L, esp_ota_get_next_update_partition(NULL)->address);
	return 1;
}

static int ota_setup(lua_State *L) {
	esp_err_t err;
	const esp_partition_t *update_partition = NULL;
	
	if(ota_handle != 0)
	{
		luaL_error(L, "OTA operation already in progress");
	}
	else
	{
		update_partition = esp_ota_get_next_update_partition(NULL);
		err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ota_handle);
		if(err != ESP_OK)
		{
			luaL_error(L, esp_err_to_name(err));
		}
	}
	return 0;
}

static int ota_flashFile(lua_State *L) {
	esp_err_t err;
	int file_fd = 0;
	int n;
	size_t len;
	char *buff = NULL;
	
	
	const char *fname = luaL_checklstring( L, 1, &len );
	const char *basename = vfs_basename( fname );
	luaL_argcheck(L, strlen(basename) <= CONFIG_FS_OBJ_NAME_LEN && strlen(fname) == len, 1, "filename invalid");
	
	if(ota_handle == 0)
	{
		luaL_error(L, "OTA update not initialized, run setup first");
	}
	else
	{
		file_fd = vfs_open(fname, "r");
		
		if(file_fd == 0)
		{
			luaL_error(L, "Could not open the file");
		}
		else
		{
			buff = malloc(sizeof(char) * OTA_READ_BUFF_SIZE);
			if(buff == NULL)
			{
				luaL_error(L, "Could not allocate data buffer");
			}
			else
			{
				do
				{
					n = vfs_read(file_fd, buff, OTA_READ_BUFF_SIZE);
					if(n > 0)
					{
						err = esp_ota_write( ota_handle, (const void *)buff, n);
						if(err != ESP_OK)
						{
							luaL_error(L, esp_err_to_name(err));
							break;
						}
					}
				}while(n == OTA_READ_BUFF_SIZE);
			}
		}
	}
	
	if(file_fd != 0)
	{
		vfs_close(file_fd);
	}
	if(buff != 0)
	{
		free(buff);
	}
	
	err = esp_ota_end(ota_handle);
	ota_handle = 0;
	if(err != ESP_OK)
	{
		luaL_error(L, "OTA operation failed");
	}
	
	return 0;
}

static const LUA_REG_TYPE ota_map[] = {
  { LSTRKEY( "bootPartition" ),    		LFUNCVAL( ota_get_boot_partition ) },
  { LSTRKEY( "runningPartition" ),    	LFUNCVAL( ota_get_running_partition ) },
  { LSTRKEY( "nextUpdatePartition" ),   LFUNCVAL( ota_get_next_update_partition ) },
  { LSTRKEY( "setup" ),     			LFUNCVAL( ota_setup ) },
  { LSTRKEY( "flashFile" ),     		LFUNCVAL( ota_flashFile ) },
  { LSTRKEY( "genpk" ),     		LFUNCVAL( ota_genpk ) },
  { LSTRKEY( "gencsr" ),     		LFUNCVAL( ota_gencsr ) },
};

NODEMCU_MODULE(OTA, "ota", ota_map, NULL);
