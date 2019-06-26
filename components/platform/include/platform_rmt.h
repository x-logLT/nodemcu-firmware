#ifndef _PLATFORM_RMT_H_
#define _PLATFORM_RMT_H_

#include "driver/rmt.h"


// define a common set of esp interrupt allocation flags for common use
#define PLATFORM_RMT_INTR_FLAGS (ESP_INTR_FLAG_LOWMED | ESP_INTR_FLAG_SHARED)

// *****************************************************************************
// RMT platform interface

/**
 * @brief Allocate an RMT channel.
 *
 * @param num_mem Number of memory blocks.
 *
 * @return
 *     - Channel number when successful
 *     - -1 if no channel available
 *
 */
int platform_rmt_allocate( uint8_t num_mem );

/**
 * @brief Release a previously allocated RMT channel.
 *
 * @param channel Channel number.
 *
 */
void platform_rmt_release( uint8_t channel );

#endif
