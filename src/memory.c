#include "memory.h"
#include "blake3.h"
#include "itsuku.h"
#include <stdio.h> // Do tymczasowego użycia (np. dla BLAKE2b)
#include <stdlib.h>
#include <string.h>

// Stała BLAKE2b-512 (dla 64-bajtowego wyjścia)
#define BLAKE2B_OUTBYTES 64

// =================================================================
// FUNKCJE POMOCNICZE WŁASNE (Implementacja operacji Endian)
// =================================================================

/**
 * @brief Konwertuje uint64_t na 8 bajtów Little Endian.
 * W Rust to jest E::u64_to_bytes(x).
 */
void u64_to_le_bytes(uint64_t x, uint8_t out[8]) {
  out[0] = (uint8_t)(x);
  out[1] = (uint8_t)(x >> 8);
  out[2] = (uint8_t)(x >> 16);
  out[3] = (uint8_t)(x >> 24);
  out[4] = (uint8_t)(x >> 32);
  out[5] = (uint8_t)(x >> 40);
  out[6] = (uint8_t)(x >> 48);
  out[7] = (uint8_t)(x >> 56);
}

/**
 * @brief Konwertuje 8 bajtów Little Endian na uint64_t.
 * W Rust to jest E::u64_from_bytes(bytes).
 */
uint64_t u64_from_le_bytes(const uint8_t bytes[8]) {
  uint64_t result = 0;
  result |= (uint64_t)bytes[0];
  result |= (uint64_t)bytes[1] << 8;
  result |= (uint64_t)bytes[2] << 16;
  result |= (uint64_t)bytes[3] << 24;
  result |= (uint64_t)bytes[4] << 32;
  result |= (uint64_t)bytes[5] << 40;
  result |= (uint64_t)bytes[6] << 48;
  result |= (uint64_t)bytes[7] << 56;
  return result;
}

// =================================================================
// ELEMENT FUNCTIONS
// =================================================================

Element Element__zero() {
  Element e;
  memset(e.data, 0, ELEMENT_SIZE);
  return e;
}

void Element__bitxor_assign(Element *self, const Element *rhs) {
  for (size_t i = 0; i < LANES; ++i) {
    self->data[i] ^= rhs->data[i];
  }
}

void Element__bitxor_assign__bytes(Element *self, const uint8_t *rhs_bytes,
                                   size_t rhs_len) {
  // W Rust: "The slice is loaded into a SIMD vector, correcting for endianness
  // before the operation."
  // Zakładamy, że rhs_bytes jest Little Endian, a my XORujemy je z Elementem
  // (u64[]). Musimy sparsować bajty do u64 z LE, a następnie XORować je z
  // danymi self->data. Używamy dostępnych bajtów (min(rhs_len, ELEMENT_SIZE)).

  size_t limit = rhs_len > ELEMENT_SIZE ? ELEMENT_SIZE : rhs_len;
  size_t lanes_to_process = limit / 8;

  for (size_t i = 0; i < lanes_to_process; ++i) {
    uint64_t rhs_u64 = u64_from_le_bytes(&rhs_bytes[i * 8]);
    self->data[i] ^= rhs_u64;
  }
}

void Element__add_assign(Element *self, const Element *rhs) {
  // W Rust: "Performs a wrapping addition assignment (`+=`) between two
  // elements using SIMD." Standardowa arytmetyka dodawania na bezstronnych int
  // w C zapewnia zawijanie.
  for (size_t i = 0; i < LANES; ++i) {
    self->data[i] += rhs->data[i];
  }
}

void Element__to_le_bytes(const Element *self,
                          uint8_t out_bytes[ELEMENT_SIZE]) {
  // Konwersja wewnętrznej tablicy u64 na 64-bajtową tablicę LE.
  // W Rust: self.data.to_le_bytes().to_array()
  for (size_t i = 0; i < LANES; ++i) {
    u64_to_le_bytes(self->data[i], &out_bytes[i * 8]);
  }
}

// =================================================================
// MEMORY FUNCTIONS
// =================================================================

Memory *Memory__new(Config config) {
  // Allocates the memory structure based on the provided configuration.
  Memory *mem = (Memory *)malloc(sizeof(Memory));
  if (!mem)
    return NULL;

  mem->config = config;
  size_t num_chunks = config.chunk_count;
  size_t chunk_size = config.chunk_size;

  mem->chunks = (Element **)calloc(num_chunks, sizeof(Element *));
  if (!mem->chunks) {
    free(mem);
    return NULL;
  }

  // Alokacja i inicjalizacja każdego chunka do zera.
  for (size_t i = 0; i < num_chunks; ++i) {
    mem->chunks[i] = (Element *)calloc(chunk_size, sizeof(Element));
    if (!mem->chunks[i]) {
      // W przypadku błędu zwalniamy już zaalokowaną pamięć
      for (size_t j = 0; j < i; ++j) {
        free(mem->chunks[j]);
      }
      free(mem->chunks);
      free(mem);
      return NULL;
    }
  }

  return mem;
}

void Memory__drop(Memory *self) {
  if (self) {
    for (size_t i = 0; i < self->config.chunk_count; ++i) {
      free(self->chunks[i]);
    }
    free(self->chunks);
    free(self);
  }
}

Element *Memory__get(Memory *self, size_t index) {
  size_t chunk_index = index / self->config.chunk_size;
  size_t element_index = index % self->config.chunk_size;

  if (chunk_index >= self->config.chunk_count) {
    return NULL;
  }

  return &self->chunks[chunk_index][element_index];
}

void Memory__get_antecedent_indices(const Config *config, const Element *chunk,
                                    size_t element_index,
                                    size_t *index_buffer) {
  // Calculates the indices of antecedent elements required to compute a
  // specific element.
  size_t antecedent_count = config->antecedent_count;

  // W Rust: assert!(element_index >= antecedent_count);
  // assert_eq!(index_buffer.len(), antecedent_count);
  if (element_index < antecedent_count) {
    // W Itsuku elementy o index < antecedent_count są inicjalizowane, nie
    // kompresowane. Powinno to być sprawdzone przez wywołującego.
    return;
  }

  // Logic is driven by the element *before* the current one.
  const Element *prev = &chunk[element_index - 1];
  uint8_t prev_bytes[ELEMENT_SIZE];
  Element__to_le_bytes(prev, prev_bytes);

  // Use the first 4 bytes of the previous element as a seed.
  uint8_t seed_4[4];
  memcpy(seed_4, &prev_bytes[0], 4);

  // Calculate a base index using Argon2-like indexing logic.
  size_t argon2_index = calculate_argon2_index(seed_4, element_index);

  size_t element_count = config->chunk_size;

  for (size_t variant = 0; variant < antecedent_count; ++variant) {
    // Apply phi variant indexing to diversify dependencies.
    size_t idx =
        calculate_phi_variant_index(element_index, argon2_index, variant);

    // W Rust: let idx_mod = idx % element_count;
    // Ten moduł jest faktycznie niepotrzebny, ponieważ
    // calculate_phi_variant_index zwraca indeks w zakresie [0,
    // element_index-1], co mieści się w chunku. Zostawiamy dla wierności,
    // chociaż element_index jest zawsze <= element_count (chunk_size).
    size_t idx_mod = idx % element_count;

    index_buffer[variant] = idx_mod;
  }
}

Element Memory__compress(const Element *antecedents, size_t antecedent_count,
                         uint64_t global_element_index,
                         const ChallengeId *challenge_id) {
  // The core compression function (Phi).

  // 1. Sum Even
  Element sum_even = Element__zero();
  size_t even_count = (antecedent_count + 1) / 2;
  for (size_t k = 0; k < even_count; ++k) {
    Element__add_assign(&sum_even, &antecedents[2 * k]);
  }

  // Apply XOR modification with global index
  // global_element_index jest XORowany z pierwszym u64 (indeks 0) elementu
  // sum_even.
  sum_even.data[0] ^= global_element_index;

  // 2. Sum Odd
  Element sum_odd = Element__zero();
  size_t odd_count = antecedent_count / 2;
  for (size_t k = 0; k < odd_count; ++k) {
    Element__add_assign(&sum_odd, &antecedents[2 * k + 1]);
  }

  // Apply XOR modification with challenge bytes
  Element__bitxor_assign__bytes(&sum_odd, challenge_id->bytes,
                                challenge_id->bytes_len);

  // 3. Variable-length Blake2b Hash
  uint8_t sum_even_bytes[ELEMENT_SIZE];
  uint8_t sum_odd_bytes[ELEMENT_SIZE];
  Element__to_le_bytes(&sum_even, sum_even_bytes);
  Element__to_le_bytes(&sum_odd, sum_odd_bytes);

  blake3_hasher S;
  blake3_hasher_init(&S);

  blake3_hasher_update(&S, sum_even_bytes, ELEMENT_SIZE);
  blake3_hasher_update(&S, sum_odd_bytes, ELEMENT_SIZE);

  Element output = Element__zero();
  blake3_hasher_finalize(&S, (uint8_t *)output.data, BLAKE2B_OUTBYTES);

  return output;
}

void Memory__build_chunk(const Config *config, size_t chunk_index,
                         Element *chunk, const ChallengeId *challenge_id) {
  // Populates a single memory chunk.

  size_t antecedent_count = config->antecedent_count;
  size_t element_count = config->chunk_size;

  // 1. Initialization: The first `antecedent_count` elements are generated.
  for (size_t element_index = 0; element_index < antecedent_count;
       ++element_index) {
    // Generowanie z: index || chunk_index || challenge_id

    // Używamy bufora do konwersji indeksów na bajty LE (8 bajtów dla u64).
    uint8_t idx_bytes[8];
    uint8_t chunk_idx_bytes[8];
    u64_to_le_bytes(element_index, idx_bytes);
    u64_to_le_bytes(chunk_index, chunk_idx_bytes);

    blake3_hasher S;
    blake3_hasher_init(&S);

    blake3_hasher_update(&S, idx_bytes, 8);
    blake3_hasher_update(&S, chunk_idx_bytes, 8);
    blake3_hasher_update(&S, challenge_id->bytes, challenge_id->bytes_len);

    // Wynik zapisujemy bezpośrednio do Elementu.
    blake3_hasher_finalize(&S, (uint8_t *)chunk[element_index].data,
                           BLAKE2B_OUTBYTES);
  }

  // 2. Iterative Construction: The remaining elements are generated.
  size_t *index_buffer = (size_t *)malloc(antecedent_count * sizeof(size_t));
  if (!index_buffer)
    return;

  Element *antecedents = (Element *)malloc(antecedent_count * sizeof(Element));
  if (!antecedents) {
    free(index_buffer);
    return;
  }

  for (size_t element_index = antecedent_count; element_index < element_count;
       ++element_index) {
    // 1. Calculate and store Antecedent Indices
    Memory__get_antecedent_indices(config, chunk, element_index, index_buffer);

    // 2. Retrieve Antecedent Elements
    for (size_t k = 0; k < antecedent_count; ++k) {
      size_t idx = index_buffer[k];
      antecedents[k] = chunk[idx];
    }

    // 3. Perform Compression
    uint64_t global_element_index =
        (uint64_t)chunk_index * (uint64_t)element_count +
        (uint64_t)element_index;

    Element new_element = Memory__compress(antecedents, antecedent_count,
                                           global_element_index, challenge_id);

    // Write the result back into the chunk
    chunk[element_index] = new_element;
  }

  free(antecedents);
  free(index_buffer);
}

void Memory__build_all_chunks(Memory *self, const ChallengeId *challenge_id) {
  // Rust uses std::thread::scope for parallelization.
  // W C użycie wątków wymaga bibliotek pthreads lub TBB.
  // Na potrzeby bazowej implementacji C, wykonamy to **sekwencyjnie**.
  // Równoległość jest cechą optymalizacyjną, a nie funkcjonalną, w tym
  // kontekście.

  for (size_t i = 0; i < self->config.chunk_count; ++i) {
    Memory__build_chunk(&self->config, i, self->chunks[i], challenge_id);
  }
}

size_t Memory__trace_element(const Memory *self, size_t leaf_index,
                             Element **out_antecedents) {
  size_t antecedent_count = self->config.antecedent_count;

  size_t chunk_index = leaf_index / self->config.chunk_size;
  if (chunk_index >= self->config.chunk_count)
    return 0;
  Element *chunk = self->chunks[chunk_index];

  size_t element_index = leaf_index % self->config.chunk_size;

  // Case 1: Base element - returns just itself as the "trace" of size 1.
  if (element_index < antecedent_count) {
    *out_antecedents = (Element *)malloc(sizeof(Element));
    if (!*out_antecedents)
      return 0;
    (*out_antecedents)[0] = chunk[element_index];
    return 1;
  }

  // Case 2: Compute the antecedents
  size_t *indices = (size_t *)malloc(antecedent_count * sizeof(size_t));
  if (!indices)
    return 0;

  Memory__get_antecedent_indices(&self->config, chunk, element_index, indices);

  // Alokacja miejsca na antecedent_count elementów i skopiowanie ich
  *out_antecedents = (Element *)malloc(antecedent_count * sizeof(Element));
  if (!*out_antecedents) {
    free(indices);
    return 0;
  }

  for (size_t i = 0; i < antecedent_count; ++i) {
    (*out_antecedents)[i] = chunk[indices[i]];
  }

  free(indices);
  return antecedent_count;
}
