TARGET = server client

all : $(TARGET)

server:
	g++ -Wall -o $@ $@.cpp -lpthread -L/usr/lib -lssl -lcrypto

client:
	g++ -Wall -o $@ $@.cpp -lpthread -L/usr/lib -lssl -lcrypto

clean:
	rm -f server
	rm -f client
