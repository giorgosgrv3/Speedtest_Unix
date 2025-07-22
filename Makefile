all:
	gcc -Wall -Wextra -pedantic -std=c99 -o client client.c
	gcc -Wall -Wextra -pedantic -std=c99 -o server server.c

clean:
	rm -f client server
