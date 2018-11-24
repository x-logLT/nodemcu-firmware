#ifndef __ARDUINO_H
#define __ARDUINO_H

#include <stdlib.h>  
#include <stdint.h>
#include <string.h>

extern "C"{
	#include"esp_timer.h"
}

#define ESP32

#define PROGMEM 
#define INPUT 0
#define OUTPUT 0
#define LOW 0
#define HIGH 1

#define boolean bool
#define byte uint8_t
#define __FlashStringHelper char

#define micros() (esp_timer_get_time())
#define millis() (esp_timer_get_time() / 1000)
#define delay(X)
#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))
#define constrain(amt,low,high) ((amt)<(low)?(low):((amt)>(high)?(high):(amt)))
#define F(x) (x)
#define pinMode(x, y) {}
#define digitalWrite(x, y) {}
#define noInterrupts() {}
#define interrupts() {}
#define pgm_read_byte(x) *(x)

#define GET_MACRO(_1,_2,NAME,...) NAME
#define random(...) GET_MACRO(__VA_ARGS__, random2, random1)(__VA_ARGS__)

extern "C"{
	long random1(long);
	long random2(long, long);
}

#endif
