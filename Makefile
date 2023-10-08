CC = clang
CFLAGS = -g -Wall -Wextra -Werror -Wpedantic $(shell pkg-config --cflags gmp)
COMMON_OBJECTS = rsa.o randstate.o numtheory.o
LFLAGS = $(shell pkg-config --libs gmp) -lm

all: keygen encrypt decrypt

encrypt: encrypt.o $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o encrypt $^ $(LFLAGS)

decrypt: decrypt.o $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o decrypt $^ $(LFLAGS)

keygen: keygen.o $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o keygen $^ $(LFLAGS)

%.o: %.c *.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f keygen encrypt decrypt *.o

format:
	$(CC)-format -i -style=file *.[ch]

scan-build: clean
	scan-build make
