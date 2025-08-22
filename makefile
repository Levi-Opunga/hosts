build:
	go build -o hosts

run:
	./hosts

clean:
	rm -f hosts

install:
	go build .;go install

install-global:
	go build .;sudo mv hosts /usr/local/bin/hosts