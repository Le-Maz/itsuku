#include "hashmap.h"
#include <stdlib.h>
#include <string.h>

// Domyślny rozmiar tablicy dla mapy haszującej
#define INITIAL_CAPACITY 64

// --- Wewnętrzne struktury ---

/**
 * @brief Pojedynczy wpis.
 */
typedef struct HashMapEntry {
  size_t key;
  void *value;
  struct HashMapEntry *next;
} HashMapEntry;

/**
 * @brief Właściwa struktura mapy haszującej.
 */
typedef struct HashMapInner {
  size_t size;                        // Aktualna liczba elementów
  size_t capacity;                    // Rozmiar tablicy (potęga 2)
  ValueDestructorFn value_destructor; // Funkcja do zwalniania wartości
  HashMapEntry **buckets;             // Tablica wskaźników do list wpisów
} HashMapInner;

// --- Funkcje pomocnicze ---

/**
 * @brief Funkcja haszująca klucz.
 */
static size_t hash(size_t key, size_t capacity) {
  // Prosta, szybka funkcja haszująca FNV-style na 64 bitach
  key = (key ^ (key >> 30)) * 0xbf58476d1ce4e5b9UL;
  key = (key ^ (key >> 27)) * 0x94d049bb133111ebUL;
  key = key ^ (key >> 31);
  return key & (capacity - 1);
}

// --- Implementacja interfejsu publicznego (PascalCase) ---

HashMap HashMap__new(ValueDestructorFn value_destructor) {
  HashMapInner *map = (HashMapInner *)malloc(sizeof(HashMapInner));
  if (!map)
    return NULL;

  map->size = 0;
  map->capacity = INITIAL_CAPACITY;
  map->value_destructor = value_destructor;

  // calloc inicjalizuje pamięć zerami (wskaźniki na NULL)
  map->buckets = (HashMapEntry **)calloc(map->capacity, sizeof(HashMapEntry *));

  if (!map->buckets) {
    free(map);
    return NULL;
  }

  // Zwracamy nieprzezroczysty wskaźnik
  return (HashMap)map;
}

void HashMap__drop(HashMap self) {
  if (!self)
    return;

  HashMapInner *map = (HashMapInner *)self;

  // Przechodzimy przez wszystkie kubełki i listy
  for (size_t i = 0; i < map->capacity; ++i) {
    HashMapEntry *entry = map->buckets[i];
    while (entry) {
      HashMapEntry *next = entry->next;

      // 1. Zwalnianie wartości, jeśli destruktor jest ustawiony
      if (map->value_destructor && entry->value) {
        map->value_destructor(entry->value);
      }

      // 2. Zwalnianie samego węzła wpisu
      free(entry);
      entry = next;
    }
  }

  free(map->buckets);
  free(map);
}

void *HashMap__get(HashMap self, size_t key) {
  if (!self)
    return NULL;

  HashMapInner *map = (HashMapInner *)self;
  size_t index = hash(key, map->capacity);

  HashMapEntry *entry = map->buckets[index];
  while (entry) {
    if (entry->key == key) {
      return entry->value;
    }
    entry = entry->next;
  }

  return NULL; // Nie znaleziono klucza
}

size_t HashMap__size(HashMap self) {
  if (!self)
    return 0;

  HashMapInner *map = (HashMapInner *)self;
  return map->size;
}

// --- Funkcja do rehaszowania (prywatna) ---

static bool HashMap__resize(HashMapInner *map, size_t new_capacity) {
  HashMapEntry **new_buckets =
      (HashMapEntry **)calloc(new_capacity, sizeof(HashMapEntry *));
  if (!new_buckets)
    return false;

  size_t old_capacity = map->capacity;
  HashMapEntry **old_buckets = map->buckets;

  map->buckets = new_buckets;
  map->capacity = new_capacity;

  // Przenosimy istniejące wpisy
  for (size_t i = 0; i < old_capacity; ++i) {
    HashMapEntry *entry = old_buckets[i];
    while (entry) {
      HashMapEntry *next = entry->next;

      // Obliczamy nowy indeks
      size_t new_index = hash(entry->key, map->capacity);

      // Wstawiamy na początek nowej listy w kubełku
      entry->next = map->buckets[new_index];
      map->buckets[new_index] = entry;

      entry = next;
    }
  }

  free(old_buckets);
  return true;
}

bool HashMap__insert(HashMap self, size_t key, void *value) {
  if (!self)
    return false;

  HashMapInner *map = (HashMapInner *)self;
  size_t index = hash(key, map->capacity);

  // Przechowywana wartość jest zawsze zwalniana, gdy następuje aktualizacja,
  // ponieważ to nowa wartość przejmuje jej miejsce.

  // 1. Sprawdzenie, czy klucz już istnieje (aktualizacja)
  HashMapEntry *entry = map->buckets[index];
  while (entry) {
    if (entry->key == key) {
      // Jeśli istniała stara wartość, zwalniamy ją
      if (map->value_destructor && entry->value) {
        map->value_destructor(entry->value);
      }
      entry->value = value;
      return true;
    }
    entry = entry->next;
  }

  // 2. Wstawienie nowego elementu (sprawdź, czy potrzebny resize)
  if (map->size >= map->capacity) {
    if (!HashMap__resize(map, map->capacity * 2)) {
      return false; // Nie udało się powiększyć mapy
    }
    // Po resize obliczamy nowy indeks
    index = hash(key, map->capacity);
  }

  // Tworzenie nowego wpisu
  HashMapEntry *new_entry = (HashMapEntry *)malloc(sizeof(HashMapEntry));
  if (!new_entry)
    return false;

  new_entry->key = key;
  new_entry->value = value;

  // Wstawienie na początek listy (łańcuchowanie)
  new_entry->next = map->buckets[index];
  map->buckets[index] = new_entry;
  map->size++;

  return true;
}

/**
 * @brief Inicjalizuje iterator dla danej mapy.
 */
HashMapIterator HashMapIterator__new(const HashMap self) {
  // Inicjalizacja: Wskaźnik na pierwszy wpis jest NULL, indeks kubełka = 0
  HashMapIterator iter = {
      .map = self,
      .bucket_index = 0,
      .entry = NULL,
  };
  return iter;
}

/**
 * @brief Pobiera następny element w mapie.
 */
bool HashMapIterator__next(HashMapIterator *self, size_t *out_key,
                           void **out_value) {
  if (!self || !self->map) {
    return false;
  }

  // Rzutowanie nieprzezroczystego wskaźnika
  const HashMapInner *map = (const HashMapInner *)self->map;

  // 1. Kontynuuj w bieżącym łańcuchu (bucket)
  if (self->entry) {
    self->entry = self->entry->next;
    if (self->entry) {
      *out_key = self->entry->key;
      *out_value = self->entry->value;
      return true;
    }
  }

  // 2. Szukaj następnego niepustego kubełka
  // Jeśli self->entry jest NULL (koniec łańcucha lub nowa iteracja),
  // szukaj od aktualnego self->bucket_index
  for (/* Brak inicjalizacji */; self->bucket_index < map->capacity;
       ++self->bucket_index) {

    // Sprawdź, czy w kubełku istnieje łańcuch
    if (map->buckets[self->bucket_index]) {

      // Znaleziono nowy łańcuch, ustaw wskaźnik i zwróć element
      self->entry = map->buckets[self->bucket_index];
      *out_key = self->entry->key;
      *out_value = self->entry->value;

      // Przesuń indeks kubełka do następnego, aby pętla for mogła
      // kontynuować od tego miejsca w następnym wywołaniu, jeśli łańcuch się
      // skończy
      self->bucket_index++;
      return true;
    }
  }

  // 3. Osiągnięto koniec mapy
  self->entry = NULL;
  return false;
}
