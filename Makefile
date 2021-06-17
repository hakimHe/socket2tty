all:
	$(CC) socket2tty.c -o socket2tty -luci -lpthread

clean:
	rm socket2tty
