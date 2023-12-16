CC = gcc

# CFLAGS += -mbranch-protection=standard
CFLAGS += -march=armv8.3-a -mbranch-protection=pac-ret -no-pie -fno-PIE
BINARY_DIR = BinaryFile/

SOURCE_DIR = SourceFile/
LANGUAGE_DIR = C/
SOURCE_FILE = $(SOURCE_DIR)$(LANGUAGE_DIR)test_simple.c

PROJ := $(BINARY_DIR)test_pac
PROJ_NOPAC := $(BINARY_DIR)test_nopac
# $(CC) $(CFLAGS) -o $(PROJ) $(SOURCE_FILE)
all: $(SOURCE_FILE)
	$(CC)  -no-pie -fno-PIE -g -o $(PROJ_NOPAC) $(SOURCE_FILE)

# python3 main.py $(BINARY_DIR)test_pac
main: main.py
	python3 main.py $(BINARY_DIR)test_nopac

run: ./BinaryFile/test_nopac
	./BinaryFile/test_nopac

gdb: ./BinaryFile/test_nopac
	gdb ./BinaryFile/test_nopac

COMPILE_PROJ = ./StandardAsm/test_pac.s
COMPILE_PROJ_NOPAC = ./StandardAsm/test_nopac.s

compile: $(SOURCE_FILE)
	$(CC) $(CFLAGS) -S $(SOURCE_FILE) -o $(COMPILE_PROJ)
	$(CC) -S  $(SOURCE_FILE) -o $(COMPILE_PROJ_NOPAC)

clean:
	rm -f $(PROJ) $(PROJ_NOPAC)

read:
	readelf -a $(PROJ_NOPAC)