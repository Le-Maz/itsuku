#ifndef MEMORY_H
#define MEMORY_H

#include "challenge_id.h"
#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ELEMENT_SIZE 64 // 64 bytes / 512 bits
#define LANES 8         // Number of u64 lanes

/**
 * @brief A single unit of data (64 bytes) within the PoW memory.
 * * Data is always interpreted as Little Endian u64 integers.
 */
typedef struct Element {
  /** The underlying data, represented as 8 u64 integers (SIMD equivalent). */
  uint64_t data[LANES];
} Element;

/**
 * @brief The main memory structure for the PoW scheme.
 */
typedef struct Memory {
  Config config;
  Element **chunks;
} Memory;

// --- Funkcje dla Element ---

/**
 * @brief Returns a new Element with all bits set to zero.
 * @return A zero-initialized Element.
 */
Element Element__zero();

/**
 * @brief Performs a bitwise XOR assignment (^) between two elements.
 */
void Element__bitxor_assign(Element *self, const Element *rhs);

/**
 * @brief Performs a bitwise XOR assignment (^) with a byte slice (interpreted
 * as LE).
 */
void Element__bitxor_assign__bytes(Element *self, const uint8_t *rhs_bytes,
                                   size_t rhs_len);

/**
 * @brief Performs a wrapping addition assignment (+) between two elements.
 */
void Element__add_assign(Element *self, const Element *rhs);

/**
 * @brief Converts the Element's internal u64 data array to a 64-byte Little
 * Endian byte array.
 * @param self The element.
 * @param out_bytes Output buffer of size ELEMENT_SIZE (64 bytes).
 */
void Element__to_le_bytes(const Element *self, uint8_t out_bytes[ELEMENT_SIZE]);

// --- Funkcje dla Memory ---

/**
 * @brief Allocates and initializes the Memory structure.
 * @param config The PoW configuration.
 * @return A newly allocated Memory structure.
 */
Memory *Memory__new(Config config);

/**
 * @brief Deallocates the Memory structure.
 */
void Memory__drop(Memory *self);

/**
 * @brief Retrieves a pointer to the element at the specified global index.
 */
Element *Memory__get(Memory *self, size_t index);

/**
 * @brief Calculates the indices of antecedent elements required to compute a
 * specific element.
 */
void Memory__get_antecedent_indices(const Config *config, const Element *chunk,
                                    size_t element_index, size_t *index_buffer);

/**
 * @brief The core compression function (Phi).
 * @param antecedents Array of antecedent elements.
 * @param antecedent_count Number of antecedents.
 * @param global_element_index The index of the new element.
 * @param challenge_id The challenge identifier.
 * @return The newly compressed Element.
 */
Element Memory__compress(const Element *antecedents, size_t antecedent_count,
                         uint64_t global_element_index,
                         const ChallengeId *challenge_id);

/**
 * @brief Populates a single memory chunk.
 */
void Memory__build_chunk(const Config *config, size_t chunk_index,
                         Element *chunk, const ChallengeId *challenge_id);

/**
 * @brief Builds the entire memory structure in parallel.
 */
void Memory__build_all_chunks(Memory *self, const ChallengeId *challenge_id);

/**
 * @brief Traces and retrieves the antecedent elements for a given leaf index.
 * @param out_antecedents A pointer to an array of Elements (to be dynamically
 * allocated/managed by C implementation).
 * @return The number of antecedents found (1 for base element, antecedent_count
 * otherwise).
 */
size_t Memory__trace_element(const Memory *self, size_t leaf_index,
                             Element **out_antecedents);

/**
 * @brief Konwertuje uint64_t na 8 bajtów w kolejności Little Endian.
 */
void u64_to_le_bytes(uint64_t x, uint8_t out[8]);

/**
 * @brief Konwertuje 8 bajtów w kolejności Little Endian na uint64_t.
 */
uint64_t u64_from_le_bytes(const uint8_t bytes[8]);

// --- Trait PartialMemory (Dla weryfikacji) ---
// Ponieważ Endianness zostało usunięte, PartialMemory jest teraz proste
typedef struct PartialMemory_Wrapper {
  void *data;
  Element (*get_element)(void *data, size_t index);
} PartialMemory_Wrapper;

#endif // MEMORY_H
