#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// --- Forward declarations for the iterator ---
// These structures are defined in hashmap.c, but the iterator must know their
// names.
typedef struct HashMapInner HashMapInner;
typedef struct HashMapEntry HashMapEntry;

/**
 * @brief Type alias for a destructor function used to free memory
 * associated with values (void *value) stored in the map.
 */
typedef void (*ValueDestructorFn)(void *);

/**
 * @brief Opaque type representing a hash map (dictionary).
 *
 * Internally, this is a pointer to HashMapInner, but callers operate on it
 * through an abstract void* handle.
 */
typedef void *HashMap;

// --- Iterator structure ---

/**
 * @brief Tracks iteration state for the hash map.
 *
 * Enables safe traversal across buckets and chained entries while
 * maintaining context for the current position in the map.
 */
typedef struct HashMapIterator {
  const HashMap map; // Pointer to the underlying map, castable to HashMapInner*
  size_t bucket_index;       // Index of the current bucket being inspected
  const HashMapEntry *entry; // Pointer to the current entry within the bucket
} HashMapIterator;

// --- HashMap API ---

HashMap HashMap__new(
    ValueDestructorFn value_destructor); // Creates a new hash map instance
void HashMap__drop(HashMap self);        // Releases the map and its values
bool HashMap__insert(HashMap self, size_t key,
                     void *value); // Inserts or overwrites a key-value pair
void *HashMap__get(HashMap self,
                   size_t key);     // Retrieves a value associated with a key
size_t HashMap__size(HashMap self); // Returns the number of stored entries

// --- Iterator API ---

/**
 * @brief Initializes an iterator for the given map.
 *
 * Must be called before beginning iteration.
 * @param self Pointer to the hash map to iterate over.
 * @return A fully initialized HashMapIterator instance.
 */
HashMapIterator HashMapIterator__new(const HashMap self);

/**
 * @brief Retrieves the next key-value pair from the map.
 *
 * Returns true if a valid element was produced, or false if the end of the
 * map was reached. Safe to call repeatedly until exhaustion.
 * Modification of the map during iteration results in undefined behavior.
 *
 * @param self Pointer to the iterator structure.
 * @param out_key Output pointer for the retrieved key.
 * @param out_value Output pointer for the retrieved value.
 */
bool HashMapIterator__next(HashMapIterator *self, size_t *out_key,
                           void **out_value);

#endif // HASHMAP_H
