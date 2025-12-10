#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Configuration parameters for the Itsuku Proof-of-Work scheme.
 *
 * This structure defines all tunable parameters used by the algorithm.
 * Each field controls a specific aspect of memory layout, work intensity,
 * or proof construction.
 */
typedef struct Config {
  /** Size of a single memory chunk, expressed in 64-byte units. */
  size_t chunk_size;

  /** Total number of allocated memory chunks. */
  size_t chunk_count;

  /** Number of antecedent elements required to compute a compressed element. */
  size_t antecedent_count;

  /** Required number of leading zero bits in the Omega hash. */
  size_t difficulty_bits;

  /** Number of tree paths used when producing a single proof (L). */
  size_t search_length;
} Config;

/**
 * @brief Returns the default configuration settings.
 *
 * Provides baseline values consistent with the Rust implementation of
 * Config::default(). The returned structure contains standard memory
 * layout parameters and difficulty settings.
 *
 * @return A fully initialized default Config structure.
 */
Config Config__default();

#endif // CONFIG_H
