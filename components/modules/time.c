#include "module.h"
#include "lauxlib.h"
#include "platform.h"

#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "lwip/apps/sntp.h"


#define ADD_TABLE_ITEM(L, key, val) \
	lua_pushinteger (L, val);	    \
	lua_setfield (L, -2, key);

static int time_get(lua_State *L)
{
	struct timeval  tv;
	gettimeofday (&tv, NULL);
	lua_pushnumber (L, tv.tv_sec);
	lua_pushnumber (L, tv.tv_usec);
	return 2;
}

static int time_set(lua_State *L)
{
	uint32_t sec = luaL_checknumber (L, 1);
	uint32_t usec = 0;
	if (lua_isnumber (L, 2))
		usec = lua_tonumber (L, 2);

	struct timeval tv = { sec, usec };
	settimeofday (&tv, NULL);

	return 0;
}

static int time_getLocal(lua_State *L)
{
	time_t now;
	struct tm date;
	
	time(&now);	
	localtime_r(&now, &date);
	
	  /* construct Lua table */
	lua_createtable (L, 0, 8);
	
	ADD_TABLE_ITEM (L, "yday", date.tm_yday + 1);
	ADD_TABLE_ITEM (L, "wday", date.tm_wday + 1);
	ADD_TABLE_ITEM (L, "year", date.tm_year + 1900);
	ADD_TABLE_ITEM (L, "mon",  date.tm_mon + 1);
	ADD_TABLE_ITEM (L, "day",  date.tm_mday);
	ADD_TABLE_ITEM (L, "hour", date.tm_hour);
	ADD_TABLE_ITEM (L, "min",  date.tm_min);
	ADD_TABLE_ITEM (L, "sec",  date.tm_sec);

	return 1;
}

static int time_setTimezone(lua_State *L)
{
	size_t l;
	const char *timezone = luaL_checklstring(L, 1, &l);
	
	setenv("TZ", timezone, 1);
	tzset();
	
	return 0;
}

static int time_uptime(lua_State *L)
{
	int64_t uptime = esp_timer_get_time();
	
	lua_pushnumber (L, uptime / 1000000);
	lua_pushnumber (L, uptime % 1000000);
	
	return 2;
}
	

static int time_initNTP(lua_State *L)
{
	size_t l;
	const char *server = luaL_checklstring(L, 1, &l);
	
	if(l < 6)
	{
		server = "pool.ntp.org";	
	}
	
	sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, server);
	sntp_init();
	
	return 0;
}

static int rtctime_epoch2cal (lua_State *L)
{
  struct tm *date;
  
  time_t now = luaL_checkint (L, 1);
  luaL_argcheck (L, now >= 0, 1, "wrong arg range");

  date = gmtime (&now);

  /* construct Lua table */
  lua_createtable (L, 0, 8);
  ADD_TABLE_ITEM (L, "yday", date->tm_yday + 1);
  ADD_TABLE_ITEM (L, "wday", date->tm_wday + 1);
  ADD_TABLE_ITEM (L, "year", date->tm_year + 1900);
  ADD_TABLE_ITEM (L, "mon",  date->tm_mon + 1);
  ADD_TABLE_ITEM (L, "day",  date->tm_mday);
  ADD_TABLE_ITEM (L, "hour", date->tm_hour);
  ADD_TABLE_ITEM (L, "min",  date->tm_min);
  ADD_TABLE_ITEM (L, "sec",  date->tm_sec);

  return 1;
}

static const LUA_REG_TYPE time_map[] = {
  { LSTRKEY("set"),            	LFUNCVAL(time_set) },
  { LSTRKEY("get"),            	LFUNCVAL(time_get) },
  { LSTRKEY("getlocal"),       	LFUNCVAL(time_getLocal) },
  { LSTRKEY("settimezone"),   	LFUNCVAL(time_setTimezone) },
  { LSTRKEY("uptime"),   		LFUNCVAL(time_uptime) },
  { LSTRKEY("initntp"),         LFUNCVAL(time_initNTP)  },
  { LSTRKEY("epoch2cal"),      	LFUNCVAL(rtctime_epoch2cal) },
  { LNILKEY, LNILVAL }
};

NODEMCU_MODULE(TIME, "time", time_map, NULL);