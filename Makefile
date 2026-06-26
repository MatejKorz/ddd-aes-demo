.PHONY: test

test:
	cmake -S . -B build
	cmake --build build
	
	# dd if=/dev/urandom of=original.bin bs=1K count=8
	yes "This is a test sentence for AES encryption and decryption." | head -c 8192 > original.bin
	cp original.bin input.bin

	@echo "Original:"
	@sha256sum original.bin

	./build/ddd-aes/readability/ddd-aes-ref-read-demo -e
	@cp input.bin encrypted.bin

	@echo "Encrypted:"
	@sha256sum encrypted.bin

	./build/ddd-aes/readability/ddd-aes-ref-read-demo -d
	@cp input.bin decrypted.bin

	@echo "Decrypted:"
	@sha256sum decrypted.bin

	cmp original.bin decrypted.bin

clean:
	rm -rf build
	rm -f original.bin input.bin encrypted.bin decrypted.bin
