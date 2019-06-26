/*
 * Copyright 2016 Dius Computing Pty Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the
 *   distribution.
 * - Neither the name of the copyright holders nor the names of
 *   its contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @author Johny Mattsson <jmattsson@dius.com.au>
 */
#include "module.h"
#include "lauxlib.h"
#include "lextra.h"
#include "wifi_common.h"
#include "ip_fmt.h"
#include "nodemcu_esp_event.h"
#include <string.h>
#include "dhcpserver/dhcpserver_options.h"


// Note: these are documented in wifi.md, update there too if changed here!
#define DEFAULT_AP_CHANNEL 11
#define DEFAULT_AP_MAXCONNS 4
#define DEFAULT_AP_BEACON 100

// --- Event handling ----------------------------------------------------
static void ap_staconn (lua_State *L, const system_event_t *evt);
static void ap_stadisconn (lua_State *L, const system_event_t *evt);
static void ap_probe_req (lua_State *L, const system_event_t *evt);
static void empty_arg (lua_State *L, const system_event_t *evt) {}

static const event_desc_t events[] =
{
  { "start",             SYSTEM_EVENT_AP_START,            empty_arg     },
  { "stop",              SYSTEM_EVENT_AP_STOP,             empty_arg     },
  { "sta_connected",     SYSTEM_EVENT_AP_STACONNECTED,     ap_staconn    },
  { "sta_disconnected",  SYSTEM_EVENT_AP_STADISCONNECTED,  ap_stadisconn },
  { "probe_req",         SYSTEM_EVENT_AP_PROBEREQRECVED,   ap_probe_req  }
};

static int event_cb[ARRAY_LEN(events)];

static void ap_staconn (lua_State *L, const system_event_t *evt)
{
  char mac[MAC_STR_SZ];
  macstr (mac, evt->event_info.sta_connected.mac);
  lua_pushstring (L, mac);
  lua_setfield (L, -2, "mac");

  lua_pushinteger (L, evt->event_info.sta_connected.aid);
  lua_setfield (L, -2, "id");
}

static void ap_stadisconn (lua_State *L, const system_event_t *evt)
{
  char mac[MAC_STR_SZ];
  macstr (mac, evt->event_info.sta_disconnected.mac);
  lua_pushstring (L, mac);
  lua_setfield (L, -2, "mac");

  lua_pushinteger (L, evt->event_info.sta_disconnected.aid);
  lua_setfield (L, -2, "id");
}

static void ap_probe_req (lua_State *L, const system_event_t *evt)
{
  char str[MAC_STR_SZ];
  macstr (str, evt->event_info.ap_probereqrecved.mac);
  lua_pushstring (L, str);
  lua_setfield (L, -2, "from");

  lua_pushinteger (L, evt->event_info.ap_probereqrecved.rssi);
  lua_setfield (L, -2, "rssi");
}

static void on_event (const system_event_t *evt)
{
  int idx = wifi_event_idx_by_id (events, ARRAY_LEN(events), evt->event_id);
  if (idx < 0 || event_cb[idx] == LUA_NOREF)
    return;

  lua_State *L = lua_getstate ();
  lua_rawgeti (L, LUA_REGISTRYINDEX, event_cb[idx]);
  lua_pushstring (L, events[idx].name);
  lua_createtable (L, 0, 5);
  events[idx].fill_cb_arg (L, evt);
  lua_call (L, 2, 0);
}

NODEMCU_ESP_EVENT(SYSTEM_EVENT_AP_START,            on_event);
NODEMCU_ESP_EVENT(SYSTEM_EVENT_AP_STOP,             on_event);
NODEMCU_ESP_EVENT(SYSTEM_EVENT_AP_STACONNECTED,     on_event);
NODEMCU_ESP_EVENT(SYSTEM_EVENT_AP_STADISCONNECTED,  on_event);
NODEMCU_ESP_EVENT(SYSTEM_EVENT_AP_PROBEREQRECVED,   on_event);

void wifi_ap_init (void)
{
  for (unsigned i = 0; i < ARRAY_LEN(event_cb); ++i)
    event_cb[i] = LUA_NOREF;
}

// --- Lua API funcs -----------------------------------------------------

static int wifi_ap_setip(lua_State *L)
{
  tcpip_adapter_ip_info_t ipInfo;
  ip_addr_t  dns;
  uint8_t opt;
  size_t len;
  const char *str;

  ip_addr_t ipAddr;
  ipAddr.type = IPADDR_TYPE_V4;

  luaL_checkanytable (L, 1);

  //memset(&ipInfo, 0, sizeof(tcpip_adapter_ip_info_t));

  lua_getfield (L, 1, "ip");
  str = luaL_checklstring (L, -1, &len);
  if(!ipaddr_aton(str, &ipAddr))
  {
    return luaL_error(L, "Could not parse IP address, aborting");
  }
  ipInfo.ip = ipAddr.u_addr.ip4;

  lua_getfield (L, 1, "gateway");
  str = luaL_checklstring (L, -1, &len);
  if(!ipaddr_aton(str, &ipAddr))
  {
    return luaL_error(L, "Could not parse Gateway address, aborting");
  }
  ipInfo.gw = ipAddr.u_addr.ip4;

  lua_getfield (L, 1, "netmask");
  str = luaL_checklstring (L, -1, &len);
  if(!ipaddr_aton(str, &ipAddr))
  {
    return luaL_error(L, "Could not parse Netmask, aborting");
  }
  ipInfo.netmask = ipAddr.u_addr.ip4;

  ESP_ERROR_CHECK(tcpip_adapter_dhcps_stop(TCPIP_ADAPTER_IF_AP));

  tcpip_adapter_set_ip_info(TCPIP_ADAPTER_IF_AP, &ipInfo);

  lua_getfield (L, 1, "dns");
  str = luaL_optlstring(L, -1, "", &len);
  if(ipaddr_aton(str, &dns))
  {

    opt = 1;
    dhcps_dns_setserver(&dns);
    tcpip_adapter_dhcps_option(TCPIP_ADAPTER_OP_SET, DOMAIN_NAME_SERVER, &opt, sizeof(opt));

  }

  ESP_ERROR_CHECK(tcpip_adapter_dhcps_start(TCPIP_ADAPTER_IF_AP));

  return 0;
}

static int wifi_ap_sethostname(lua_State *L)
{
  size_t l;
  esp_err_t err;
  const char *hostname = luaL_checklstring(L, 1, &l);

  err = tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_AP, hostname);

  if (err != ESP_OK)
    return luaL_error (L, "failed to set hostname, code %d", err);

  lua_pushboolean (L, err==ESP_OK);

  return 1;
}

static int wifi_ap_config (lua_State *L)
{
  luaL_checkanytable (L, 1);
  bool save = luaL_optbool (L, 2, DEFAULT_SAVE);

  wifi_config_t cfg;
  memset (&cfg, 0, sizeof (cfg));

  lua_getfield (L, 1, "ssid");
  size_t len;
  const char *str = luaL_checklstring (L, -1, &len);
  if (len > sizeof (cfg.ap.ssid))
    len = sizeof (cfg.ap.ssid);
  strncpy ((char *)cfg.ap.ssid, str, len);
  cfg.ap.ssid_len = len;

  lua_getfield (L, 1, "pwd");
  str = luaL_optlstring (L, -1, "", &len);
  if (len > sizeof (cfg.ap.password))
    len = sizeof (cfg.ap.password);
  strncpy ((char *)cfg.ap.password, str, len);

  lua_getfield (L, 1, "auth");
  int authmode = luaL_optint (L, -1, WIFI_AUTH_WPA2_PSK);
  if (authmode < 0 || authmode >= WIFI_AUTH_MAX)
    return luaL_error (L, "unknown auth mode %d", authmode);
  cfg.ap.authmode = authmode;

  lua_getfield (L, 1, "channel");
  cfg.ap.channel = luaL_optint (L, -1, DEFAULT_AP_CHANNEL);

  lua_getfield (L, 1, "hidden");
  cfg.ap.ssid_hidden = luaL_optbool (L, -1, false);

  lua_getfield (L, 1, "max");
  cfg.ap.max_connection = luaL_optint (L, -1, DEFAULT_AP_MAXCONNS);

  lua_getfield (L, 1, "beacon");
  cfg.ap.beacon_interval = luaL_optint (L, -1, DEFAULT_AP_BEACON);
  
  SET_SAVE_MODE(save);
  
  lua_getfield(L, 1, "phymode");
  uint8_t phymode = luaL_optnumber(L, -1, PHY_BGN);
  esp_err_t err = esp_wifi_set_protocol(WIFI_IF_AP, phymode);
  if (err != ESP_OK)
    return luaL_error (L, "failed to set wifi phy mode, code %d", err);

  err = esp_wifi_set_config (WIFI_IF_AP, &cfg);
  return (err == ESP_OK) ?
    0 : luaL_error (L, "failed to set wifi config, code %d", err);
}

static int wifi_ap_getmac (lua_State *L)
{
  return wifi_getmac(WIFI_IF_AP, L);
}

static int wifi_ap_on (lua_State *L)
{
  return wifi_on (L, events, ARRAY_LEN(events), event_cb);
}


const LUA_REG_TYPE wifi_ap_map[] =
{
  { LSTRKEY( "setip" ),      		  LFUNCVAL( wifi_ap_setip )         },
  { LSTRKEY( "sethostname" ), 		  LFUNCVAL( wifi_ap_sethostname )   },
  { LSTRKEY( "config" ),              LFUNCVAL( wifi_ap_config )        },
  { LSTRKEY( "on" ),                  LFUNCVAL( wifi_ap_on )            },
  { LSTRKEY( "getmac" ),              LFUNCVAL( wifi_ap_getmac )        },

  { LNILKEY, LNILVAL }
};
