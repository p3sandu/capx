CC = gcc
CFLAGS = -g -Wall -Wextra
LIBS = -lpcap
SOURCES = src/capx.c src/utils.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = bin/capx

.PHONY: clean test

$(TARGET): $(OBJECTS)
	$(CC) -g -o $@ $^ $(LIBS)
	sudo ./bin/capx

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
