#ifndef MEMORY_H
#define MEMORY_H

#include "challenge_id.h"
#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ELEMENT_SIZE 64 // 64 bytes / 512 bits
#define LANES 8         // Number of u64 lanes in an element

/**
 * @brief A single memory element (64 bytes) in the Itsuku PoW memory.
 *
 * Always interpreted as an array of Little Endian u64 integers.
 */
typedef struct Element {
  /** The element's data, represented as 8 u64 integers (SIMD-equivalent). */
  uint64_t data[LANES];
} Element;

/**
 * @brief Main memory structure for the PoW scheme.
 */
typedef struct Memory {
  Config config;    // PoW configuration
  Element **chunks; // Array of chunk pointers
} Memory;

// --- Element Functions ---

/**
 * @brief Returns a new Element with all bits set to zero.
 * @return Zero-initialized Element.
 */
Element Element__zero();

/**
 * @brief Performs bitwise XOR assignment between two elements.
 */
void Element__bitxor_assign(Element *self, const Element *rhs);

/**
 * @brief Performs bitwise XOR assignment with a byte slice (interpreted as
 * Little Endian).
 */
void Element__bitxor_assign__bytes(Element *self, const uint8_t *rhs_bytes,
                                   size_t rhs_len);

/**
 * @brief Performs wrapping addition assignment between two elements.
 */
void Element__add_assign(Element *self, const Element *rhs);

/**
 * @brief Converts an Element's internal u64 array to a 64-byte Little Endian
 * array.
 * @param self The element to convert.
 * @param out_bytes Output buffer (must be ELEMENT_SIZE = 64 bytes).
 */
void Element__to_le_bytes(const Element *self, uint8_t out_bytes[ELEMENT_SIZE]);

// --- Memory Functions ---

/**
 * @brief Allocates and initializes a Memory structure with the given config.
 * @param config PoW configuration.
 * @return Pointer to the newly allocated Memory.
 */
Memory *Memory__new(Config config);

/**
 * @brief Deallocates a Memory structure and all its chunks.
 */
void Memory__drop(Memory *self);

/**
 * @brief Retrieves a pointer to an element by global index.
 * @param self The memory instance.
 * @param index Global element index.
 * @return Pointer to the Element at the specified index.
 */
Element *Memory__get(Memory *self, size_t index);

/**
 * @brief Computes the antecedent element indices for a given element.
 * @param config The PoW configuration.
 * @param chunk Pointer to the chunk.
 * @param element_index Index within the chunk.
 * @param index_buffer Output array to hold antecedent indices.
 */
void Memory__get_antecedent_indices(const Config *config, const Element *chunk,
                                    size_t element_index, size_t *index_buffer);

/**
 * @brief Core compression function (Phi) to compute a new Element.
 * @param antecedents Array of antecedent Elements.
 * @param antecedent_count Number of antecedents.
 * @param global_element_index Global index of the element being computed.
 * @param challenge_id Challenge identifier.
 * @return Newly compressed Element.
 */
Element Memory__compress(const Element *antecedents, size_t antecedent_count,
                         uint64_t global_element_index,
                         const ChallengeId *challenge_id);

/**
 * @brief Builds a single chunk of memory using the provided challenge.
 */
void Memory__build_chunk(const Config *config, size_t chunk_index,
                         Element *chunk, const ChallengeId *challenge_id);

/**
 * @brief Builds all memory chunks in parallel.
 */
void Memory__build_all_chunks(Memory *self, const ChallengeId *challenge_id);

/**
 * @brief Traces and retrieves antecedent elements for a leaf element.
 * @param out_antecedents Pointer to an array of Elements (allocated
 * dynamically).
 * @return Number of antecedents found (1 for base element, antecedent_count
 * otherwise).
 */
size_t Memory__trace_element(const Memory *self, size_t leaf_index,
                             Element **out_antecedents);

/**
 * @brief Converts a uint64_t to 8 bytes in Little Endian order.
 */
void u64_to_le_bytes(uint64_t x, uint8_t out[8]);

/**
 * @brief Converts 8 bytes in Little Endian order to uint64_t.
 */
uint64_t u64_from_le_bytes(const uint8_t bytes[8]);

// --- PartialMemory Wrapper (for verification/testing) ---

/**
 * @brief Simple wrapper to emulate PartialMemory trait.
 */
typedef struct PartialMemory_Wrapper {
  void *data;
  Element (*get_element)(void *data, size_t index);
} PartialMemory_Wrapper;

#endif // MEMORY_H
