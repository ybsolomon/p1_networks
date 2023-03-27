All: server client standalone

server: server.c util.c cJSON/cJSON.c
	gcc -g -o server server.c util.c cJSON/cJSON.c

client: client.c util.c cJSON/cJSON.c
	gcc -g -o client client.c util.c cJSON/cJSON.c

standalone: standalone.c util.c cJSON/cJSON.c
	gcc -g -o standalone standalone.c util.c cJSON/cJSON.c