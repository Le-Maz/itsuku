#include "config.h"
#include <stddef.h>

/**
 * @brief Zwraca domyślne ustawienia konfiguracyjne Itsuku.
 *
 * Parametry domyślne pochodzą z implementacji Config::default() w Rust:
 * - chunk_size: 1 << 15 (32,768)
 * - chunk_count: 1 << 10 (1,024)
 * - antecedent_count: 4
 * - difficulty_bits: 24
 * - search_length: 9 (L)
 *
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
