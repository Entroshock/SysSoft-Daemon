# Makefile for manufacturing daemon

CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS =

DAEMON_SRC = daemon.c
CLIENT_SRC = client.c
DAEMON_OBJ = $(DAEMON_SRC:.c=.o)
CLIENT_OBJ = $(CLIENT_SRC:.c=.o)
DAEMON_BIN = manufacturing_daemon
CLIENT_BIN = manufacturing_client

.PHONY: all clean install

all: $(DAEMON_BIN) $(CLIENT_BIN)

$(DAEMON_BIN): $(DAEMON_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

$(CLIENT_BIN): $(CLIENT_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c config.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(DAEMON_OBJ) $(CLIENT_OBJ) $(DAEMON_BIN) $(CLIENT_BIN)

install:
	mkdir -p /media/sf_CA1/manufacturing/upload
	mkdir -p /media/sf_CA1/manufacturing/report
	mkdir -p /media/sf_CA1/manufacturing/backup
	mkdir -p /media/sf_CA1/manufacturing/logs
	chmod 755 /media/sf_CA1/manufacturing/upload
	chmod 755 /media/sf_CA1/manufacturing/report
	chmod 755 /media/sf_CA1/manufacturing/backup
	touch /media/sf_CA1/manufacturing/logs/changes.log
	touch /media/sf_CA1/manufacturing/logs/error.log
	touch /media/sf_CA1/manufacturing/logs/info.log
	chmod 644 /media/sf_CA1/manufacturing/logs/*.log
	cp $(DAEMON_BIN) /usr/sbin/
	cp $(CLIENT_BIN) /usr/bin/
	cp manufacturing_daemon.init /etc/init.d/manufacturing_daemon
	chmod 755 /etc/init.d/manufacturing_daemon
	update-rc.d manufacturing_daemon defaults