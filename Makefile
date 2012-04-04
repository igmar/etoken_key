
.c.o:
	$(CC) -Wall -g -c -o $@ $<

all: etoken_key

etoken_key: etoken_key.o sha2.o
	$(CC) -o $@ $^ -lp11

clean:
	rm -f *.o core etoken_key
