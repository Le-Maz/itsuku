#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// --- Forward Declarations dla iteratora ---
// Struktury te są definiowane w hashmap.c, ale iterator musi znać ich nazwy.
typedef struct HashMapInner HashMapInner;
typedef struct HashMapEntry HashMapEntry;

/**
 * @brief Typ wskaźnika na funkcję destruktora, używaną do zwalniania pamięci
 * wartości (void *value) przechowywanych w mapie.
 */
typedef void (*ValueDestructorFn)(void *);

/**
 * @brief Nieprzezroczysty typ reprezentujący mapę haszującą (hash map /
 * dictionary).
 */
typedef void *HashMap;

// --- Nowa struktura dla iteratora ---

/**
 * @brief Struktura śledząca stan iteracji przez HashMap.
 * Umożliwia bezpieczne przechodzenie przez kubełki i listy (łańcuchy).
 */
typedef struct HashMapIterator {
  // Wskaźnik na bazową mapę. Musi być rzutowany na HashMapInner*.
  const HashMap map;
  // Aktualny indeks kubełka (bucket index).
  size_t bucket_index;
  // Wskaźnik na aktualny wpis w liście wewnątrz kubełka.
  const HashMapEntry *entry;
} HashMapIterator;

// --- Funkcje dla HashMap (bez zmian) ---
HashMap HashMap__new(ValueDestructorFn value_destructor);
void HashMap__drop(HashMap self);
bool HashMap__insert(HashMap self, size_t key, void *value);
void *HashMap__get(HashMap self, size_t key);
size_t HashMap__size(HashMap self);

// --- Funkcje dla Iteratora (NOWE) ---

/**
 * @brief Inicjalizuje iterator dla danej mapy.
 * Należy użyć tej funkcji przed rozpoczęciem iteracji.
 * @param self Wskaźnik na HashMap, po której ma odbywać się iteracja.
 * @return Zwraca zainicjalizowany HashMapIterator.
 */
HashMapIterator HashMapIterator__new(const HashMap self);

/**
 * @brief Pobiera następny element w mapie.
 * Zwraca true, jeśli znaleziono następny element, lub false, jeśli osiągnięto
 * koniec. UWAGA: Iteracja jest bezpieczna, ale modyfikacja mapy podczas
 * iteracji jest niezdefiniowana.
 * @param self Wskaźnik na strukturę iteratora (HashMapIterator).
 * @param out_key Wskaźnik do zapisania klucza.
 * @param out_value Wskaźnik do zapisania wartości.
 */
bool HashMapIterator__next(HashMapIterator *self, size_t *out_key,
                           void **out_value);

#endif // HASHMAP_H
