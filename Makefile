
honeybee: src/honeybee.c src/connection.c src/server.c src/honeybee.h
	@echo "Building honeybee binary ..."
	@gcc -g src/honeybee.c src/connection.c src/server.c -o honeybee

