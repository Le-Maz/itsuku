#ifndef ITSUKU_H
#define ITSUKU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Computes an Argon2-style index from a given seed and original element
 * index.
 *
 * Implements logic similar to RFC 9106, Section 3.4.2. Used to determine
 * the position of a dependency element in memory for the Itsuku PoW.
 *
 * @param seed_bytes The first 4 bytes of a memory element, interpreted as
 *                   a little-endian u32.
 * @param original_index The index of the element currently being computed.
 * @return The calculated Argon2-style dependency index.
 */
size_t calculate_argon2_index(uint8_t seed_bytes[4], size_t original_index);

/**
 * @brief Computes the phi variant index for dependency selection.
 *
 * Used in the Itsuku PoW scheme to select which antecedent elements are
 * used to compute a new memory element. Each variant identifier (0–11)
 * corresponds to a different selection rule.
 *
 * @param original_index The index of the element being computed.
 * @param argon2_index The index previously calculated by
 * calculate_argon2_index.
 * @param variant_identifier Integer in the range 0–11 selecting the dependency
 * rule.
 * @return The calculated antecedent index within the chunk.
 */
size_t calculate_phi_variant_index(size_t original_index, size_t argon2_index,
                                   size_t variant_identifier);

#endif // ITSUKU_H
