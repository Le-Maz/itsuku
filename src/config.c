#include "config.h"
#include <stddef.h>

/**
 * @brief Returns the default Itsuku configuration settings.
 *
 * Default parameters correspond to the Rust implementation of
 * Config::default():
 * - chunk_size: 1 << 15 (32,768)
 * - total_chunk_count: 1 << 10 (1,024)
 * - antecedent_element_count: 4
 * - omega_difficulty_bits: 24
 * - proof_search_length: 9
 */
Config Config__default() {
  return (Config){
      .chunk_size = 1 << 15,
      .chunk_count = 1 << 10,
      .antecedent_count = 4,
      .difficulty_bits = 24,
      .search_length = 9,
  };
}
