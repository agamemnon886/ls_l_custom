CC=gcc
CFLAGS+= -Wall -fsanitize=address -pedantic -g
TARGET=ls_l_custom
RM=rm -f

all: $(TARGET)

$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	$(RM) $(TARGET)
