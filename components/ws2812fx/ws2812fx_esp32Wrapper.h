#ifndef __WS2812FX_ESP32_H
#define __WS2812FX_ESP32_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct 
{
	uint8_t value;
	char name[5];
}ws2812fxWrapper_pixelOrderStruct;

struct ws2812fx;
typedef struct ws2812fx ws2812fx_t;

ws2812fx_t* ws2812fxWrapper_create(uint16_t n, uint8_t p, uint8_t t);
void ws2812fxWrapper_destroy(ws2812fx_t *inst);

void ws2812fxWrapper_init(ws2812fx_t *inst);
void ws2812fxWrapper_service(ws2812fx_t *inst);
void ws2812fxWrapper_start(ws2812fx_t *inst);
void ws2812fxWrapper_stop(ws2812fx_t *inst);
void ws2812fxWrapper_resume(ws2812fx_t *inst);
void ws2812fxWrapper_setMode(ws2812fx_t *inst, uint8_t m);
void ws2812fxWrapper_setModeSeg(ws2812fx_t *inst, uint8_t seg, uint8_t m);
void ws2812fxWrapper_setOptions(ws2812fx_t *inst, uint8_t seg, uint8_t o);

void ws2812fxWrapper_setBrightness(ws2812fx_t *inst, uint8_t b);

void ws2812fx_trigger(ws2812fx_t *inst);
const char* ws2812fxWrapper_getModeName(ws2812fx_t *inst, uint8_t m);
uint8_t ws2812fxWrapper_getModeCount();

const char* ws2812fxWrapper_getPixelOrderName(uint8_t m);
uint8_t ws2812fxWrapper_getPixelOrderCount(void);
uint8_t ws2812fxWrapper_getPixelOrderByName(char *name);

#ifdef __cplusplus
}
#endif

#endif
