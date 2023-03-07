All: server client

server: server.c util.c
	gcc -g -o server server.c util.c cJSON/cJSON.c

client: client.c util.c cJSON/cJSON.c
	gcc -g -o client client.c util.c cJSON/cJSON.c