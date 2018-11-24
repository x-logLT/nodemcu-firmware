#include "module.h"
#include "lauxlib.h"
#include "lmem.h"
#include "platform.h"

#include <string.h>

#include "ws2812fx_esp32Wrapper.h"

ws2812fx_t *inst;

static int ws2812fx_init(lua_State *L)
{
    int gpio_num = luaL_checkinteger( L, 1 );
	
    int len =  luaL_checkinteger( L, 2 );
	
	char* pixel = luaL_checkstring(L, 3);
	
	uint8_t pixelOrder = ws2812fxWrapper_getPixelOrderByName(pixel);
	
	if(pixelOrder != 0)
	{
		inst = ws2812fxWrapper_create(len, gpio_num, pixelOrder);
	}
	else
	{
		luaL_error(L, "Pixel Order unsupported");
	}
	
	return 0;
}

static int ws2812fx_service(lua_State *L)
{
	ws2812fxWrapper_service(inst);
	return 0;
}

static int ws2812fx_setmode(lua_State *L)
{
	int mode = luaL_checkinteger( L, 1 );
	
	ws2812fxWrapper_setMode(inst, mode);
	return 0;
}

static int ws2812fx_getmodename(lua_State *L)
{
	int mode = luaL_checkinteger( L, 1 );
	
	lua_pushstring(L, ws2812fxWrapper_getModeName(inst, mode));
	return 1;	
}

static int ws2812fx_start(lua_State *L)
{
	ws2812fxWrapper_start(inst);
	return 0;
}

static int ws2812fx_stop(lua_State *L)
{
	ws2812fxWrapper_stop(inst);
	return 0;
}

static int ws2812fx_resume(lua_State *L)
{
	ws2812fxWrapper_resume(inst);
	return 0;
}

static int ws2812fx_setBrightness(lua_State *L)
{
	int b = luaL_checkinteger( L, 1 );
	
	ws2812fxWrapper_setBrightness(inst, b);
	return 0;
}

static int ws2812fx_getPixelOrderName(lua_State *L)
{
	int i = luaL_checkinteger( L, 1 );
	
	lua_pushstring(L, ws2812fxWrapper_getPixelOrderName(i));
	
	return 1;
}

static int ws2812fx_getModeCount(lua_State *L)
{
	lua_pushinteger(L, ws2812fxWrapper_getModeCount());
	
	return 1;
}


static const LUA_REG_TYPE ws2812fx_map[] =
{
  { LSTRKEY( "init" ),    			LFUNCVAL( ws2812fx_init )},
  { LSTRKEY( "service" ),   		LFUNCVAL( ws2812fx_service )},
  { LSTRKEY( "setmode" ),   		LFUNCVAL( ws2812fx_setmode )},
  { LSTRKEY( "getmodename" ),   	LFUNCVAL( ws2812fx_getmodename )},
  { LSTRKEY( "start" ),   			LFUNCVAL( ws2812fx_start )},
  { LSTRKEY( "stop" ),   			LFUNCVAL( ws2812fx_stop )},
  { LSTRKEY( "resume" ),   			LFUNCVAL( ws2812fx_resume )},
  { LSTRKEY( "setbrightness" ),		LFUNCVAL( ws2812fx_setBrightness )},
  { LSTRKEY( "getpixelordername" ),	LFUNCVAL( ws2812fx_getPixelOrderName )},
  { LSTRKEY( "getmodecount" ),		LFUNCVAL( ws2812fx_getModeCount )},
  { LNILKEY, LNILVAL}
};


NODEMCU_MODULE(WS2812FX, "ws2812fx", ws2812fx_map, NULL);