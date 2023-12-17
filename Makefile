CC = gcc

# CFLAGS += -mbranch-protection=standard
NOPAC_CFLAGS += -no-pie -fno-PIE -g
PAC_CFLAGS += -march=armv8.3-a -mbranch-protection=pac-ret -no-pie -fno-PIE -g
BINARY_DIR = BinaryFile/

SOURCE_DIR = SourceFile/
LANGUAGE_DIR = C/
SOURCE_FILE = $(SOURCE_DIR)$(LANGUAGE_DIR)test_simple.c

PROJ_PAC := $(BINARY_DIR)test_pac
PROJ_NOPAC := $(BINARY_DIR)test_nopac
all: $(SOURCE_FILE)
	$(CC) $(NOPAC_CFLAGS) -o $(PROJ_NOPAC) $(SOURCE_FILE)
	$(CC) $(PAC_CFLAGS) -o $(PROJ_PAC) $(SOURCE_FILE)

main: main.py
	python3 main.py $(BINARY_DIR)test_nopac
	python3 main.py $(BINARY_DIR)test_pac

run: ./BinaryFile/test_nopac
	./BinaryFile/test_nopac


clean:
	rm -f $(PROJ_PAC) $(PROJ_NOPAC)

read:
	readelf -a $(PROJ_NOPAC)