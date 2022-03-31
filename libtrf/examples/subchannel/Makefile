prog:
	make server
	make client
server:
	gcc -Wall --std=gnu99 -L ../.. -I ../../include server.c -o server -ltrf -lfabric -lprotobuf-c -O0 -g
	cp -r ../../conf .
client:
	gcc -Wall --std=gnu99 -L ../.. -I ../../include client.c -o client -ltrf -lfabric -lprotobuf-c -O0 -g
clean:
	rm -f client server