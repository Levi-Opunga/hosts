build:
	go build -o hosts-cli

run:
	./hosts-cli

clean:
	rm -f hosts-cli

install:
	go build .;go install

install-global:
	go build .;sudo mv hosts-cli /usr/local/bin/hosts-cli