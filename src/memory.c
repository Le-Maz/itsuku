#include "memory.h"
#include "blake3.h"
#include "itsuku.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Blake3 output size in bytes (64 bytes / 512 bits)
#define BLAKE3_OUTBYTES 64

// =================================================================
// HELPER FUNCTIONS (Endian Conversion)
// =================================================================

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
  size_t limit = rhs_len > ELEMENT_SIZE ? ELEMENT_SIZE : rhs_len;
  size_t lanes_to_process = limit / 8;

  for (size_t i = 0; i < lanes_to_process; ++i) {
    uint64_t rhs_u64 = u64_from_le_bytes(&rhs_bytes[i * 8]);
    self->data[i] ^= rhs_u64;
  }
}

void Element__add_assign(Element *self, const Element *rhs) {
  for (size_t i = 0; i < LANES; ++i) {
    self->data[i] += rhs->data[i];
  }
}

void Element__to_le_bytes(const Element *self,
                          uint8_t out_bytes[ELEMENT_SIZE]) {
  for (size_t i = 0; i < LANES; ++i) {
    u64_to_le_bytes(self->data[i], &out_bytes[i * 8]);
  }
}

// =================================================================
// MEMORY FUNCTIONS
// =================================================================

Memory *Memory__new(Config config) {
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

  for (size_t i = 0; i < num_chunks; ++i) {
    mem->chunks[i] = (Element *)calloc(chunk_size, sizeof(Element));
    if (!mem->chunks[i]) {
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
  size_t antecedent_count = config->antecedent_count;

  if (element_index < antecedent_count) {
    return;
  }

  const Element *prev = &chunk[element_index - 1];
  uint8_t prev_bytes[ELEMENT_SIZE];
  Element__to_le_bytes(prev, prev_bytes);

  uint8_t seed_4[4];
  memcpy(seed_4, &prev_bytes[0], 4);

  size_t argon2_index = calculate_argon2_index(seed_4, element_index);
  size_t element_count = config->chunk_size;

  for (size_t variant = 0; variant < antecedent_count; ++variant) {
    size_t idx =
        calculate_phi_variant_index(element_index, argon2_index, variant);
    index_buffer[variant] = idx % element_count;
  }
}

Element Memory__compress(const Element *antecedents, size_t antecedent_count,
                         uint64_t global_element_index,
                         const ChallengeId *challenge_id) {
  Element sum_even = Element__zero();
  size_t even_count = (antecedent_count + 1) / 2;
  for (size_t k = 0; k < even_count; ++k) {
    Element__add_assign(&sum_even, &antecedents[2 * k]);
  }
  sum_even.data[0] ^= global_element_index;

  Element sum_odd = Element__zero();
  size_t odd_count = antecedent_count / 2;
  for (size_t k = 0; k < odd_count; ++k) {
    Element__add_assign(&sum_odd, &antecedents[2 * k + 1]);
  }
  Element__bitxor_assign__bytes(&sum_odd, challenge_id->bytes,
                                challenge_id->bytes_len);

  uint8_t sum_even_bytes[ELEMENT_SIZE];
  uint8_t sum_odd_bytes[ELEMENT_SIZE];
  Element__to_le_bytes(&sum_even, sum_even_bytes);
  Element__to_le_bytes(&sum_odd, sum_odd_bytes);

  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, sum_even_bytes, ELEMENT_SIZE);
  blake3_hasher_update(&hasher, sum_odd_bytes, ELEMENT_SIZE);

  Element output = Element__zero();
  blake3_hasher_finalize(&hasher, (uint8_t *)output.data, BLAKE3_OUTBYTES);

  return output;
}

void Memory__build_chunk(const Config *config, size_t chunk_index,
                         Element *chunk, const ChallengeId *challenge_id) {
  size_t antecedent_count = config->antecedent_count;
  size_t element_count = config->chunk_size;

  for (size_t element_index = 0; element_index < antecedent_count;
       ++element_index) {
    uint8_t idx_bytes[8], chunk_idx_bytes[8];
    u64_to_le_bytes(element_index, idx_bytes);
    u64_to_le_bytes(chunk_index, chunk_idx_bytes);

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, idx_bytes, 8);
    blake3_hasher_update(&hasher, chunk_idx_bytes, 8);
    blake3_hasher_update(&hasher, challenge_id->bytes, challenge_id->bytes_len);

    blake3_hasher_finalize(&hasher, (uint8_t *)chunk[element_index].data,
                           BLAKE3_OUTBYTES);
  }

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
    Memory__get_antecedent_indices(config, chunk, element_index, index_buffer);
    for (size_t k = 0; k < antecedent_count; ++k) {
      antecedents[k] = chunk[index_buffer[k]];
    }

    uint64_t global_element_index =
        (uint64_t)chunk_index * (uint64_t)element_count +
        (uint64_t)element_index;

    Element new_element = Memory__compress(antecedents, antecedent_count,
                                           global_element_index, challenge_id);

    chunk[element_index] = new_element;
  }

  free(antecedents);
  free(index_buffer);
}

void Memory__build_all_chunks(Memory *self, const ChallengeId *challenge_id) {
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

  if (element_index < antecedent_count) {
    *out_antecedents = (Element *)malloc(sizeof(Element));
    if (!*out_antecedents)
      return 0;
    (*out_antecedents)[0] = chunk[element_index];
    return 1;
  }

  size_t *indices = (size_t *)malloc(antecedent_count * sizeof(size_t));
  if (!indices)
    return 0;

  Memory__get_antecedent_indices(&self->config, chunk, element_index, indices);

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
