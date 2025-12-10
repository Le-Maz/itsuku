# =================================================================
# Itsuku PoW Scheme - Makefile (Wersja z podziałem testów i przykładem)
# =================================================================

# --- Konfiguracja kompilatora i flagi ---
CC = gcc
# Dodajemy -Isrc i -Itests, aby kompilator znajdował pliki nagłówkowe projektu.
CFLAGS = -Wall -Wextra -std=c99 -Isrc -Itests -O3
LDFLAGS = -lm -lblake3
AR = ar rcs

# --- Definicje katalogów ---
SRC_DIR = src
OUT_DIR = out
TEST_DIR = tests
EXAMPLE_DIR = example
TEST_OBJ_DIR = $(OUT_DIR)/tests_obj
EXAMPLE_OBJ_DIR = $(OUT_DIR)/example_obj

# --- Pliki źródłowe projektu (SRC) ---
ITS_SOURCES_LIST = itsuku.c memory.c merkle_tree.c config.c challenge_id.c hashmap.c proof.c
ITS_SOURCES = $(patsubst %, $(SRC_DIR)/%, $(ITS_SOURCES_LIST))

# --- Pliki źródłowe testów (TESTS) ---
TEST_SOURCES_LIST = main_runner.c test_core.c test_memory.c test_merkle.c test_proof.c
TEST_SOURCES = $(patsubst %, $(TEST_DIR)/%, $(TEST_SOURCES_LIST))

# --- Pliki źródłowe przykładu (EXAMPLE) ---
EXAMPLE_SOURCE = $(EXAMPLE_DIR)/solver_cli.c

# --- Cele końcowe i pliki generowane ---
ITS_LIB = $(OUT_DIR)/libitsuku.a
TEST_EXE = $(OUT_DIR)/itsuku_test_runner
SOLVER_EXE = $(OUT_DIR)/solver_cli

# Obiekty projektu (w out/)
ITS_OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OUT_DIR)/%.o, $(ITS_SOURCES))

# Obiekty testów (w out/tests_obj/)
TEST_OBJECTS = $(patsubst $(TEST_DIR)/%.c, $(TEST_OBJ_DIR)/%.o, $(TEST_SOURCES))

# Obiekt przykładu (w out/example_obj/)
SOLVER_OBJECT = $(patsubst $(EXAMPLE_DIR)/%.c, $(EXAMPLE_OBJ_DIR)/%.o, $(EXAMPLE_SOURCE))

# =================================================================
# CELE DO TWORZENIA KATALOGÓW
# =================================================================

.PHONY: all clean test run rebuild example

all: $(OUT_DIR) $(TEST_OBJ_DIR) $(EXAMPLE_OBJ_DIR) $(ITS_LIB) $(TEST_EXE) $(SOLVER_EXE)

$(OUT_DIR):
	@mkdir -p $(OUT_DIR)

$(TEST_OBJ_DIR):
	@mkdir -p $(TEST_OBJ_DIR)

$(EXAMPLE_OBJ_DIR):
	@mkdir -p $(EXAMPLE_OBJ_DIR)

# =================================================================
# REGULY BUDOWANIA PROJEKTU ITSUKU (Biblioteka Statyczna)
# =================================================================

# Kompilacja plików źródłowych Itsuku na obiekty .o w folderze out/
$(OUT_DIR)/%.o: $(SRC_DIR)/%.c | $(OUT_DIR)
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Tworzenie biblioteki statycznej libitsuku.a
$(ITS_LIB): $(ITS_OBJECTS)
	@echo "AR $@"
	$(AR) $@ $(ITS_OBJECTS)

# =================================================================
# REGULY BUDOWANIA TESTÓW
# =================================================================

# Kompilacja plików testowych na obiekty .o w folderze out/tests_obj
$(TEST_OBJ_DIR)/%.o: $(TEST_DIR)/%.c | $(TEST_OBJ_DIR)
	@echo "Compiling Test $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Łączenie testów w plik wykonywalny
$(TEST_EXE): $(TEST_OBJECTS) $(ITS_LIB)
	@echo "LINK $@"
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

# =================================================================
# REGULY BUDOWANIA PRZYKŁADU (SOLVER CLI)
# =================================================================

# Kompilacja solver_cli.c
$(EXAMPLE_OBJ_DIR)/%.o: $(EXAMPLE_DIR)/%.c | $(EXAMPLE_OBJ_DIR)
	@echo "Compiling Example $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Łączenie solver_cli
$(SOLVER_EXE): $(SOLVER_OBJECT) $(ITS_LIB)
	@echo "LINK $@"
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

# =================================================================
# CELE GŁÓWNE
# =================================================================

test: $(TEST_EXE)
	@echo "RUN Tests from $(OUT_DIR)"
	@./$(TEST_EXE)

run: test

example: $(SOLVER_EXE)
	@echo "RUN Example Solver: Try './out/solver_cli -r -d 8'"

rebuild: clean all test

clean:
	@echo "Cleaning up..."
	@rm -rf $(OUT_DIR)
