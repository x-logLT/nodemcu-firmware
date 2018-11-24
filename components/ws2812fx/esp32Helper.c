#include "platform.h"
#include "esp_system.h"


void espShow( uint8_t pin, uint8_t *pixels, uint32_t numBytes, bool is800KHz) {
	platform_ws2812_setup(pin, 1, pixels, numBytes);
	platform_ws2812_send();
	platform_ws2812_release();
}

long random1(long max)
{
	return esp_random() % max;
}

long random2(long min, long max)
{
	long rand = esp_random() % max;
	return rand < min ? min : rand;
}
