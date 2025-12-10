#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Configuration parameters for the Itsuku Proof-of-Work scheme.
 */
typedef struct Config {
  /** The size of a single memory chunk (in 64-byte elements). */
  size_t chunk_size;
  /** The total number of memory chunks. */
  size_t chunk_count;
  /** The number of antecedent elements required to compute a compressed
   * element. */
  size_t antecedent_count;
  /** The required number of leading zeros in the Omega hash. */
  size_t difficulty_bits;
  /** The number of tree paths used for a single proof (L). */
  size_t search_length;
} Config;

/**
 * @brief Returns the default configuration settings.
 * @return The default Config struct.
 */
Config Config__default();

#endif // CONFIG_H
