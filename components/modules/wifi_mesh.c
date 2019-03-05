#include "module.h"
#include "lauxlib.h"
#include "lextra.h"
#include "lmem.h"
#include "wifi_common.h"
#include "ip_fmt.h"
#include "lwip/ip_addr.h"
#include "task/task.h"

#include "esp_mesh.h"
#include "esp_mesh_internal.h"

#include <string.h>

enum
{
	MESH_AUTO_ROOT = 0,
	MESH_FIXED_ROOT = 1,
	MESH_IS_ROOT = 2
};

static task_handle_t mesh_event;
static mesh_addr_t mesh_parent_addr;
static int mesh_layer = -1;

int CB_meshRefs[MESH_EVENT_MAX];

static void handle_mesh_event (task_param_t param, task_prio_t prio)
{
  mesh_event_t *ev = (mesh_event_t *)param;
  (void)prio;
  
  int cbRef = CB_meshRefs[ev->id];
  mesh_addr_t id;
  int nargs=0;
  
  static uint8_t last_layer = 0;

  lua_State *L = lua_getstate();
  if (cbRef != LUA_NOREF) {
	lua_rawgeti(L, LUA_REGISTRYINDEX, cbRef);
	switch (ev->id)
	{
		case MESH_EVENT_STARTED:
			esp_mesh_get_id(&id);
			//push mac id.addr
			nargs = 1;
			mesh_layer = esp_mesh_get_layer();
			break;
		case MESH_EVENT_STOPPED:
			mesh_layer = esp_mesh_get_layer();
			break;
		case MESH_EVENT_CHILD_CONNECTED:
			lua_pushinteger(L, ev->info.child_connected.aid);
			//push mac ev->info.child_connected.mac
			nargs = 1;
			break;
		case MESH_EVENT_CHILD_DISCONNECTED:
			lua_pushinteger(L, ev->info.child_disconnected.aid);
			//push mac ev->info.child_disconnected.mac
			nargs = 1;
			break;
		case MESH_EVENT_ROUTING_TABLE_ADD:
		case MESH_EVENT_ROUTING_TABLE_REMOVE:
			lua_pushinteger(L, ev->info.routing_table.rt_size_change);
			lua_pushinteger(L, ev->info.routing_table.rt_size_new);
			nargs = 2;
			break;
		case MESH_EVENT_NO_PARENT_FOUND:
			lua_pushinteger(L, ev->info.no_parent.scan_times);
			nargs = 1;
			break;
		case MESH_EVENT_PARENT_CONNECTED:
			esp_mesh_get_id(&id);
			mesh_layer = ev->info.connected.self_layer;
			memcpy(&mesh_parent_addr.addr, ev->info.connected.connected.bssid, 6);
			
			lua_pushinteger(L, last_layer);
			lua_pushinteger(L, mesh_layer);
			//push mac mesh_parent_addr.addr
			nargs = 2;
			
			last_layer = mesh_layer;
			if (esp_mesh_is_root()) {
				tcpip_adapter_dhcpc_start(TCPIP_ADAPTER_IF_STA);
			}
			break;
		case MESH_EVENT_PARENT_DISCONNECTED:
			lua_pushinteger(L, ev->info.disconnected.reason);
			nargs = 1;
			mesh_layer = esp_mesh_get_layer();
			break;
		case MESH_EVENT_LAYER_CHANGE:
			mesh_layer = ev->info.layer_change.new_layer;
			lua_pushinteger(L, last_layer);
			lua_pushinteger(L, mesh_layer);
			last_layer = mesh_layer;
			nargs = 2;
			break;
		case MESH_EVENT_ROOT_ADDRESS:
			//push mac ev->info.root_addr.addr
			//nargs = 1;
			break;
		case MESH_EVENT_ROOT_GOT_IP:
			//push ip ev->info.got_ip.ip_info.ip
			//push ip ev->info.got_ip.ip_info.netmask
			//push ip ev->info.got_ip.ip_info.gw
			//nargs = 3;
			break;
		case MESH_EVENT_ROOT_LOST_IP:
			break;
		case MESH_EVENT_VOTE_STARTED:
			lua_pushinteger(L, ev->info.vote_started.attempts);
			lua_pushinteger(L, ev->info.vote_started.reason);
			//push mac ev->info.vote_started.rc_addr.addr
			nargs = 2;
			break;
		case MESH_EVENT_VOTE_STOPPED:
			break;
		case MESH_EVENT_ROOT_SWITCH_REQ:
			lua_pushinteger(L, ev->info.switch_req.reason);
			//push mac ev->info.switch_req.rc_addr.addr
			nargs = 1;
			break;
		case MESH_EVENT_ROOT_SWITCH_ACK:
			mesh_layer = esp_mesh_get_layer();
			esp_mesh_get_parent_bssid(&mesh_parent_addr);
			lua_pushinteger(L, mesh_layer);
			//print mac mesh_parent_addr.addr
			nargs = 1;
			break;
		case MESH_EVENT_TODS_STATE:
			lua_pushinteger(L, ev->info.toDS_state);
			nargs = 1;
			break;
		case MESH_EVENT_ROOT_FIXED:
			lua_pushboolean(L, ev->info.root_fixed.is_fixed ? 1 : 0);
			nargs = 1;
			break;
		case MESH_EVENT_ROOT_ASKED_YIELD:
			//push mac ev->info.root_conflict.addr
			lua_pushinteger(L, ev->info.root_conflict.rssi);
			lua_pushinteger(L, ev->info.root_conflict.capacity);
			nargs = 2;
			break;
		case MESH_EVENT_CHANNEL_SWITCH:
			break;
		case MESH_EVENT_SCAN_DONE:
			lua_pushinteger(L, ev->info.scan_done.number);
			nargs = 1;
			break;
		case MESH_EVENT_NETWORK_STATE:
		case MESH_EVENT_STOP_RECONNECTION:
		//case MESH_EVENT_FIND_NETWORK:
		//case MESH_EVENT_ROUTER_SWITCH:
		default:
			break;
	}
	lua_call(L, nargs, 0);
  }

  free (ev);
}

void mesh_event_cb(mesh_event_t event)
{
	mesh_event_t *ev = (mesh_event_t *)malloc (sizeof (mesh_event_t));
	if (!ev)
		return false;
	
	memcpy(ev, &event, sizeof(mesh_event_t));
	
	if (!task_post_medium (mesh_event, (task_param_t)ev)) {
		free (ev);
		return false;
	}
	return true;
}

void wifi_mesh_on(lua_State *L)
{
	int *refptr = NULL;
	
	const char *name = luaL_checkstring(L, 1);
	if (!name) return luaL_error(L, "need callback name");
	
	//search callback name
	
	if (refptr == NULL)
		return luaL_error(L, "invalid callback name");
	if (lua_isfunction(L, 2) || lua_islightfunction(L, 2)) {
		lua_pushvalue(L, 2);
		luaL_unref(L, LUA_REGISTRYINDEX, *refptr);
		*refptr = luaL_ref(L, LUA_REGISTRYINDEX);
	} else if (lua_isnil(L, 2)) {
		luaL_unref(L, LUA_REGISTRYINDEX, *refptr);
		*refptr = LUA_NOREF;
	} else {
		return luaL_error(L, "invalid callback function");
	}
	
	return 0;
}

void wifi_mesh_config(lua_State *L)
{
	mesh_cfg_t cfg = MESH_INIT_CONFIG_DEFAULT();
	uint8_t layers = 0;
	float vote = 0;
	int expiration = 0;
	uint8_t root;
	size_t len;
	char *str;
	uint8_t i;
	esp_err_t err;
	const char *fmts[] = {
		  "%hhx%hhx%hhx%hhx%hhx%hhx",
		  "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		  "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
		  "%hhx %hhx %hhx %hhx %hhx %hhx",
		  NULL
		};
	

	lua_getfield (L, 1, "layers");
	layers = luaL_optinteger (L, -1, 6);
	
	lua_getfield (L, 1, "votepercentage");
	vote = luaL_optlong (L, -1, 1.0);
	
	lua_getfield (L, 1, "expiration");
	expiration = luaL_optinteger (L, -1, 10);
	
	lua_getfield (L, 1, "root");
	root = luaL_optinteger (L, -1, MESH_AUTO_ROOT);
	
	lua_getfield (L, 1, "channel");
	cfg.channel = luaL_optinteger (L, -1, 1);
	
	lua_getfield (L, 1, "router_ssid");
	str = luaL_checklstring (L, -1, &len);
	cfg.router.ssid_len = len > sizeof(cfg.router.ssid) ? sizeof(cfg.router.ssid) : len;
	memcpy((uint8_t *) &cfg.router.ssid, str, sizeof(cfg.router.ssid));
	
	lua_getfield (L, 1, "router_pwd");
	str = luaL_checklstring (L, -1, &len);
	memcpy((uint8_t *) &cfg.router.password, str, sizeof(cfg.router.password));
	
	lua_getfield (L, 1, "router_bssid");
	if (lua_isstring (L, -1))
	{
		str = luaL_checklstring (L, -1, &len);
		for (i = 0; fmts[i]; ++i)
		{
			if (sscanf (str, fmts[i],
				&cfg.router.bssid[0], &cfg.router.bssid[1], &cfg.router.bssid[2],
				&cfg.router.bssid[3], &cfg.router.bssid[4], &cfg.router.bssid[5]) == 6)
			{
				return luaL_error (L, "invalid Router BSSID: %s", str);
				break;
			}
		}
	}
	
	lua_getfield (L, 1, "conns");
	cfg.mesh_ap.max_connection = luaL_optinteger (L, -1, 6);
	
	lua_getfield (L, 1, "pwd");
	str = luaL_checklstring (L, -1, &len);
	memcpy((uint8_t *) &cfg.mesh_ap.password, str, sizeof(cfg.mesh_ap.password));
	
	lua_getfield (L, 1, "meshid");
	if (lua_isstring (L, -1))
	{
		str = luaL_checklstring (L, -1, &len);
		for (unsigned i = 0; fmts[i]; ++i)
		{
			if (sscanf (str, fmts[i],
				&cfg.mesh_id.addr[0], &cfg.mesh_id.addr[1], &cfg.mesh_id.addr[2],
				&cfg.mesh_id.addr[3], &cfg.mesh_id.addr[4], &cfg.mesh_id.addr[5]) == 6)
			{
				return luaL_error (L, "invalid Mesh ID: %s", str);
				break;
			}
		}
	}
	
	err = tcpip_adapter_dhcps_stop(TCPIP_ADAPTER_IF_AP);
	if (err != ESP_OK)
		return luaL_error (L, "failed to set stop DHCP server, code %d", err);
	//ESP_ERROR_CHECK(tcpip_adapter_dhcpc_stop(TCPIP_ADAPTER_IF_STA));
	
	err = esp_mesh_init();
	if (err != ESP_OK)
		return luaL_error (L, "failed to init mesh, code %d", err);
    err = esp_mesh_set_max_layer(layers);
	if (err != ESP_OK)
		return luaL_error (L, "failed to set mesh layers, code %d", err);
    err = esp_mesh_set_vote_percentage(vote);
	if (err != ESP_OK)
		return luaL_error (L, "failed to set mesh vote percentage, code %d", err);
    err = esp_mesh_set_ap_assoc_expire(expiration);
	if (err != ESP_OK)
		return luaL_error (L, "failed to set mesh expire time, code %d", err);
	
	switch(root)
	{
		case MESH_AUTO_ROOT:
			esp_mesh_fix_root(0);
			break;
		case MESH_FIXED_ROOT:
			esp_mesh_fix_root(1);
			err = esp_mesh_set_type(MESH_LEAF);
			break;
		case MESH_IS_ROOT:
			esp_mesh_fix_root(1);
			err = esp_mesh_set_type(MESH_ROOT);
			break;
		default:
			break;
	}
	
	if (err != ESP_OK)
		return luaL_error (L, "failed to set mesh type, code %d", err);
	
	cfg.event_cb = &mesh_event_cb;
	
    err = esp_mesh_set_config(&cfg);
	if (err != ESP_OK)
		return luaL_error (L, "failed to configure mesh network, code %d", err);
	
	return 0;
}


void wifi_mesh_start(lua_State *L)
{
	esp_err_t err = esp_mesh_start();
	
	return err != ESP_OK ? luaL_error (L, "failed to set wifi auto-connect, code %d", err) : 0;
}

void wifi_mesh_init(void)
{
	mesh_event = task_get_id (handle_mesh_event);
	memset(CB_meshRefs, LUA_NOREF, sizeof(int) * MESH_EVENT_MAX);
	return ;
}

const LUA_REG_TYPE wifi_mesh_map[] = {
  { LSTRKEY( "config" ),       	LFUNCVAL( wifi_mesh_config ) },
  { LSTRKEY( "start" ), 		LFUNCVAL( wifi_mesh_start )},
  { LSTRKEY( "on" ), 		    LFUNCVAL( wifi_mesh_on )},
  
  { LSTRKEY( "MESH_AUTO" ),   	LNUMVAL( MESH_AUTO_ROOT ) },
  { LSTRKEY( "MESH_LEAF" ),  	LNUMVAL( MESH_FIXED_ROOT ) },
  { LSTRKEY( "MESH_ROOT" ), 	LNUMVAL( MESH_IS_ROOT ) },

  { LNILKEY, LNILVAL }
};

