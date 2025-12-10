#ifndef ITSUKU_H
#define ITSUKU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Funkcje pomocnicze z lib.rs

/**
 * @brief Computes argon2 index from a given seed and original index.
 * * Implements logic similar to RFC 9106, Section 3.4.2.
 * @param seed_bytes The first 4 bytes of a memory element, treated as u32
 * little-endian.
 * @param original_index The index of the element being computed.
 * @return The calculated Argon2-style index.
 */
size_t calculate_argon2_index(uint8_t seed_bytes[4], size_t original_index);

/**
 * @brief Computes the phi variant index for dependency selection.
 * @param original_index The index of the element being computed.
 * @param argon2_index The index calculated by calculate_argon2_index.
 * @param variant_identifier A value from 0 to 11 to select the dependency rule.
 * @return The calculated antecedent index within the chunk.
 */
size_t calculate_phi_variant_index(size_t original_index, size_t argon2_index,
                                   size_t variant_identifier);

#endif // ITSUKU_H
