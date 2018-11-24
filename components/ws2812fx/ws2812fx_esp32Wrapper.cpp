#include "WS2812FX.h"
#include "ws2812fx_esp32Wrapper.h"

#include <string.h>

struct ws2812fx{
	void *obj;
};

const ws2812fxWrapper_pixelOrderStruct ws2812fxWrapper_pixelOrder[] = {
	{NEO_RGB, "RGB"},
	{NEO_RBG, "RBG"},
	{NEO_GRB, "GRB"},
	{NEO_GBR, "GBR"},
	{NEO_BRG, "BRG"},
	{NEO_BGR, "BGR"},
	{NEO_WRGB, "WRGB"},
	{NEO_WRBG, "WRBG"},
	{NEO_WGRB, "WGRB"},
	{NEO_WGBR, "WGBR"},
	{NEO_WBRG, "WBRG"},
	{NEO_WBGR, "WBGR"},
	{NEO_RWGB, "RWGB"},
	{NEO_RWBG, "RWBG"},
	{NEO_RGWB, "RGWB"},
	{NEO_RGBW, "RGBW"},
	{NEO_RBWG, "RBWG"},
	{NEO_RBGW, "RBGW"},
	{NEO_GWRB, "GWRB"},
	{NEO_GWBR, "GWBR"},
	{NEO_GRWB, "GRWB"},
	{NEO_GRBW, "GRBW"},
	{NEO_GBWR, "GBWR"},
	{NEO_GBRW, "GBRW"},
	{NEO_BWRG, "BWRG"},
	{NEO_BWGR, "BWGR"},
	{NEO_BRWG, "BRWG"},
	{NEO_BRGW, "BRGW"},
	{NEO_BGWR, "BGWR"},
	{NEO_BGRW, "BGRW"},	
};

ws2812fx_t* ws2812fxWrapper_create(uint16_t n, uint8_t p, uint8_t t)
{
	ws2812fx_t *inst;
	WS2812FX *obj;
	
	inst = (typeof(inst))malloc(sizeof(*inst));
	obj = new WS2812FX(n, p, t);
	inst->obj = obj;
	
	return inst;
}

void ws2812fxWrapper_destroy(ws2812fx_t *inst)
{
	if(inst == NULL)
		return;
	
	delete static_cast<WS2812FX *>(inst->obj);
    free(inst);
}

void ws2812fxWrapper_init(ws2812fx_t *inst)
{
	WS2812FX *obj;
	
	if(inst == NULL)
		return;
	
	obj = static_cast<WS2812FX *>(inst->obj);
	obj->init();
}

void ws2812fxWrapper_service(ws2812fx_t *inst)
{
	WS2812FX *obj;
	
	if(inst == NULL)
		return;
	
	obj = static_cast<WS2812FX *>(inst->obj);
	obj->service();
}

void ws2812fxWrapper_start(ws2812fx_t *inst)
{
	WS2812FX *obj;
	
	if(inst == NULL)
		return;
	
	obj = static_cast<WS2812FX *>(inst->obj);
	obj->start();
}

void ws2812fxWrapper_stop(ws2812fx_t *inst)
{
	WS2812FX *obj;
	
	if(inst == NULL)
		return;
	
	obj = static_cast<WS2812FX *>(inst->obj);
	obj->stop();
}

void ws2812fxWrapper_resume(ws2812fx_t *inst)
{
	WS2812FX *obj;
	
	if(inst == NULL)
		return;
	
	obj = static_cast<WS2812FX *>(inst->obj);
	obj->resume();
}

void ws2812fxWrapper_setMode(ws2812fx_t *inst, uint8_t m)
{
	WS2812FX *obj;
	
	if(inst == NULL)
		return;
	
	obj = static_cast<WS2812FX *>(inst->obj);
	obj->setMode(m);
}

void ws2812fxWrapper_setModeSeg(ws2812fx_t *inst, uint8_t seg, uint8_t m)
{
	WS2812FX *obj;
	
	if(inst == NULL)
		return;
	
	obj = static_cast<WS2812FX *>(inst->obj);
	obj->setMode(seg, m);
}

void ws2812fxWrapper_setOptions(ws2812fx_t *inst, uint8_t seg, uint8_t o)
{
	WS2812FX *obj;
	
	if(inst == NULL)
		return;
	
	obj = static_cast<WS2812FX *>(inst->obj);
	obj->setOptions(seg, o);
}

void ws2812fxWrapper_setBrightness(ws2812fx_t *inst, uint8_t b)
{
	WS2812FX *obj;
	
	if(inst == NULL)
		return;
	
	obj = static_cast<WS2812FX *>(inst->obj);
	obj->setBrightness(b);
}

void ws2812fxWrapper_trigger(ws2812fx_t *inst)
{
	WS2812FX *obj;
	
	if(inst == NULL)
		return;
	
	obj = static_cast<WS2812FX *>(inst->obj);
	obj->trigger();
}

const char* ws2812fxWrapper_getModeName(ws2812fx_t *inst, uint8_t m)
{
	WS2812FX *obj;
	
	if(inst == NULL)
		return NULL;
	
	obj = static_cast<WS2812FX *>(inst->obj);
	return obj->getModeName(m);
}

uint8_t ws2812fxWrapper_getModeCount()
{
	return MODE_COUNT;
}

const char* ws2812fxWrapper_getPixelOrderName(uint8_t m)
{
	if(m < sizeof(ws2812fxWrapper_pixelOrder))
	{
		return ws2812fxWrapper_pixelOrder[m].name;
	}
	
	return NULL;
}

uint8_t ws2812fxWrapper_getPixelOrderCount(void)
{
	return sizeof(ws2812fxWrapper_pixelOrder);
}

uint8_t ws2812fxWrapper_getPixelOrderByName(char *name)
{
	uint8_t i = 0;
	uint8_t retVal = 0;
	if(name != NULL)
	{
		for(i = 0; i < sizeof(ws2812fxWrapper_pixelOrder); i++)
		{
			if(strcasecmp(name, ws2812fxWrapper_pixelOrder[i].name) == 0)
			{
				retVal = ws2812fxWrapper_pixelOrder[i].value;
				break;
			}
		}
	}
	
	return retVal;
}

