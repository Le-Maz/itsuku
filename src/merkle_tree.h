#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include "challenge_id.h"
#include "config.h"
#include "hashmap.h"
#include "memory.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief A Merkle Tree implementation tailored for the Itsuku PoW scheme.
 */
typedef struct MerkleTree {
  Config config;
  /** The size of each node in bytes. */
  size_t node_size;
  /** Flat storage for all tree nodes (leaves and intermediate nodes). */
  uint8_t *nodes;
  size_t nodes_len;
} MerkleTree;

// --- Funkcje dla MerkleTree ---

/**
 * @brief Calculates the required size (in bytes) for Merkle Tree nodes.
 */
size_t MerkleTree__calculate_node_size(const Config *config);

/**
 * @brief Allocates and initializes a new Merkle Tree.
 */
MerkleTree *MerkleTree__new(Config config);

/**
 * @brief Deallocates the MerkleTree structure.
 */
void MerkleTree__drop(MerkleTree *self);

/**
 * @brief Retrieves a constant reference to the node data at the specified
 * index.
 */
const uint8_t *MerkleTree__get_node(const MerkleTree *self, size_t index);

/**
 * @brief Computes the hash for a leaf node (a memory element).
 */
void MerkleTree__compute_leaf_hash(const ChallengeId *challenge_id,
                                   const Element *element, size_t node_size,
                                   uint8_t *output);

/**
 * @brief Populates all leaf nodes of the tree.
 */
void MerkleTree__compute_leaf_hashes(MerkleTree *self,
                                     const ChallengeId *challenge_id,
                                     const Memory *memory);

/**
 * @brief Computes all intermediate nodes up to the root.
 */
void MerkleTree__compute_intermediate_nodes(MerkleTree *self,
                                            const ChallengeId *challenge_id);

/**
 * @brief Returns the indices of the left and right children for a given parent
 * index.
 */
void MerkleTree__children_of(size_t index, size_t *left_index,
                             size_t *right_index);

/**
 * @brief Traces the Merkle path (authentication path) for a given node index.
 * @param nodes A pointer to a hash map (BTreeMap) to store the result (index ->
 * hash bytes).
 */
void MerkleTree__trace_node(const MerkleTree *self, size_t index,
                            HashMap nodes);

// --- Trait PartialMerkleTree (Dla weryfikacji) ---
// Ponieważ Endianness zostało usunięte, PartialMerkleTree jest teraz proste
typedef struct PartialMerkleTree_Wrapper {
  void *data;
  const uint8_t *(*get_node)(void *data, size_t index, size_t *out_len);
} PartialMerkleTree_Wrapper;

#endif // MERKLE_TREE_H
