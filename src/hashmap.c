#include "hashmap.h"
#include <stdlib.h>
#include <string.h>

// Default initial bucket array size for the hash map
#define INITIAL_CAPACITY 64

// --- Internal Structures ---

/**
 * @brief Represents a single key-value entry in the hash map.
 *        Implemented as a node in a linked list (separate chaining).
 */
typedef struct HashMapEntry {
  size_t key;                // The key for this entry
  void *value;               // Pointer to the stored value
  struct HashMapEntry *next; // Pointer to the next entry in the chain
} HashMapEntry;

/**
 * @brief The actual internal hash map structure.
 *        The public API exposes only an opaque pointer.
 */
typedef struct HashMapInner {
  size_t size;                        // Current number of stored elements
  size_t capacity;                    // Bucket count (always a power of 2)
  ValueDestructorFn value_destructor; // Optional destructor for stored values
  HashMapEntry *
      *buckets; // Array of bucket pointers (each bucket = linked list)
} HashMapInner;

// --- Helper Functions ---

/**
 * @brief Hash function for a size_t key.
 *
 * Uses a fast 64-bit FNV-style mixing function and masks with capacity-1
 * to compute the bucket index.
 */
static size_t hash(size_t key, size_t capacity) {
  key = (key ^ (key >> 30)) * 0xbf58476d1ce4e5b9UL;
  key = (key ^ (key >> 27)) * 0x94d049bb133111ebUL;
  key = key ^ (key >> 31);
  return key & (capacity - 1);
}

// --- Public API Implementation ---

/**
 * @brief Creates a new hash map with INITIAL_CAPACITY buckets.
 *
 * The returned object is an opaque pointer to HashMapInner.
 */
HashMap HashMap__new(ValueDestructorFn value_destructor) {
  HashMapInner *map = (HashMapInner *)malloc(sizeof(HashMapInner));
  if (!map)
    return NULL;

  map->size = 0;
  map->capacity = INITIAL_CAPACITY;
  map->value_destructor = value_destructor;

  // calloc zero-initializes the bucket array so all pointers start as NULL
  map->buckets = (HashMapEntry **)calloc(map->capacity, sizeof(HashMapEntry *));
  if (!map->buckets) {
    free(map);
    return NULL;
  }

  return (HashMap)map; // Return opaque pointer
}

/**
 * @brief Deallocates the entire hash map, including all entries and values.
 */
void HashMap__drop(HashMap self) {
  if (!self)
    return;

  HashMapInner *map = (HashMapInner *)self;

  // Traverse buckets and free all chained entries
  for (size_t i = 0; i < map->capacity; ++i) {
    HashMapEntry *entry = map->buckets[i];
    while (entry) {
      HashMapEntry *next = entry->next;

      // Call user-provided destructor if available
      if (map->value_destructor && entry->value) {
        map->value_destructor(entry->value);
      }

      free(entry);
      entry = next;
    }
  }

  free(map->buckets);
  free(map);
}

/**
 * @brief Retrieves the value associated with a key, or NULL if not found.
 */
void *HashMap__get(HashMap self, size_t key) {
  if (!self)
    return NULL;

  HashMapInner *map = (HashMapInner *)self;
  size_t index = hash(key, map->capacity);

  HashMapEntry *entry = map->buckets[index];
  while (entry) {
    if (entry->key == key)
      return entry->value;
    entry = entry->next;
  }

  return NULL; // Key not found
}

/**
 * @brief Returns the number of elements stored in the map.
 */
size_t HashMap__size(HashMap self) {
  if (!self)
    return 0;

  HashMapInner *map = (HashMapInner *)self;
  return map->size;
}

// --- Resize (Private) ---

/**
 * @brief Internal function that resizes the bucket array to new_capacity.
 *
 * Recomputes indices and moves all entries into the new bucket structure.
 */
static bool HashMap__resize(HashMapInner *map, size_t new_capacity) {
  HashMapEntry **new_buckets =
      (HashMapEntry **)calloc(new_capacity, sizeof(HashMapEntry *));
  if (!new_buckets)
    return false;

  size_t old_capacity = map->capacity;
  HashMapEntry **old_buckets = map->buckets;

  map->buckets = new_buckets;
  map->capacity = new_capacity;

  // Rehash existing entries into the new bucket array
  for (size_t i = 0; i < old_capacity; ++i) {
    HashMapEntry *entry = old_buckets[i];
    while (entry) {
      HashMapEntry *next = entry->next;

      size_t new_index = hash(entry->key, map->capacity);

      entry->next = map->buckets[new_index];
      map->buckets[new_index] = entry;

      entry = next;
    }
  }

  free(old_buckets);
  return true;
}

/**
 * @brief Inserts or updates a key-value pair.
 *
 * If the key already exists, its value is replaced and the old value freed
 * via the destructor. If not, a new entry is inserted.
 *
 * Automatically resizes the map when size >= capacity.
 */
bool HashMap__insert(HashMap self, size_t key, void *value) {
  if (!self)
    return false;

  HashMapInner *map = (HashMapInner *)self;
  size_t index = hash(key, map->capacity);

  // Check for existing key (update case)
  HashMapEntry *entry = map->buckets[index];
  while (entry) {
    if (entry->key == key) {
      // Replace old value
      if (map->value_destructor && entry->value)
        map->value_destructor(entry->value);

      entry->value = value;
      return true;
    }
    entry = entry->next;
  }

  // Grow map if needed
  if (map->size >= map->capacity) {
    if (!HashMap__resize(map, map->capacity * 2))
      return false;

    index = hash(key, map->capacity); // Recompute index after resize
  }

  // Insert a new entry at the front of the bucket chain
  HashMapEntry *new_entry = (HashMapEntry *)malloc(sizeof(HashMapEntry));
  if (!new_entry)
    return false;

  new_entry->key = key;
  new_entry->value = value;
  new_entry->next = map->buckets[index];
  map->buckets[index] = new_entry;

  map->size++;
  return true;
}

// --- Iterator Implementation ---

/**
 * @brief Creates a new iterator positioned before the first element.
 */
HashMapIterator HashMapIterator__new(const HashMap self) {
  HashMapIterator iter = {
      .map = self,       // Store the opaque pointer
      .bucket_index = 0, // Start at bucket 0
      .entry = NULL,     // No entry selected yet
  };
  return iter;
}

/**
 * @brief Retrieves the next key-value pair from the map.
 *
 * Returns:
 * - true  if a key-value pair was produced
 * - false if the iteration reached the end
 */
bool HashMapIterator__next(HashMapIterator *self, size_t *out_key,
                           void **out_value) {
  if (!self || !self->map)
    return false;

  const HashMapInner *map = (const HashMapInner *)self->map;

  // 1. Continue inside the current linked list if possible
  if (self->entry) {
    self->entry = self->entry->next;
    if (self->entry) {
      *out_key = self->entry->key;
      *out_value = self->entry->value;
      return true;
    }
  }

  // 2. Scan forward for the next non-empty bucket
  for (; self->bucket_index < map->capacity; ++self->bucket_index) {
    if (map->buckets[self->bucket_index]) {

      self->entry = map->buckets[self->bucket_index];
      *out_key = self->entry->key;
      *out_value = self->entry->value;

      self->bucket_index++; // Prepare for next call
      return true;
    }
  }

  // 3. End of map
  self->entry = NULL;
  return false;
}
