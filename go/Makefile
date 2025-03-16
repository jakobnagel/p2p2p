bin:
	mkdir -p bin

bin/server: bin
	go build -o bin/server ./cmd/server

bin/client: bin
	go build -o bin/client ./cmd/client

all: bin/server bin/client

run-server:
	go run ./cmd/server/*.go

run-client:
	go run ./cmd/client/*.go

clean:
	rm -rf bin