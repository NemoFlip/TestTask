all: build run

build:
	docker-compose build

run:
	docker-compose up

clean:
	docker-compose down