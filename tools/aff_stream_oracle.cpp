// Optional development oracle: AFFLIB's stream API, never linked into Rust.
#include <cstdio>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>
#include <afflib.h>
#ifdef _WIN32
#include <io.h>
#endif
int main(int argc, char **argv) {
    if (argc != 2) return 2;
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    AFFILE *image = af_open(argv[1], O_RDONLY, 0);
    if (!image) return 3;
    unsigned char buffer[65536];
    for (;;) {
        int count = af_read(image, buffer, sizeof buffer);
        if (count < 0) { af_close(image); return 4; }
        if (!count) break;
        if (fwrite(buffer, 1, count, stdout) != (size_t)count) {
            af_close(image); return 5;
        }
    }
    return af_close(image) ? 6 : 0;
}
