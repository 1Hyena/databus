// SPDX-License-Identifier: MIT
#include "../../databus.h"
#include <cstdlib>
#include <ctime>

static void log(DATABUS::ERROR, const char *line) noexcept;
static void log(const char *fmt, ...) noexcept;

int main(int argc, char **argv) {
    DATABUS databus;

    databus.set_logger(
        [](DATABUS::ERROR error, const char *line) noexcept {
            log(error, line);
        }
    );

    databus.set_memcap(4096);

    log("%s", "starting the program");

    if (!databus.init()) {
        log("%s", "failed to initialize");

        return EXIT_FAILURE;
    }

    for (size_t i=0; i<10; ++i) {
        DATABUS::ERROR error = databus.set_payload(i, "");

        switch (error) {
            case DATABUS::NO_ERROR: {
                log("database entry %lu has been set", i);
                continue;
            }
            case DATABUS::OUT_OF_MEMORY: {
                const auto memcap = databus.get_memcap();

                if (memcap < 5000) {
                    databus.set_memcap(memcap + 256);
                    log("databus memcap is now %lu", databus.get_memcap());
                    --i;
                    continue;
                }

                [[fallthrough]];
            }
            default: break;
        }

        log(error, databus.to_string(error));
        break;
    }

    databus.deinit();

    log("%s", "exiting the program");

    return EXIT_SUCCESS;
}

static void log(const char *fmt, ...) noexcept {
    char stackbuf[256];
    const char *line{};
    char *bufptr = stackbuf;
    size_t bufsz = sizeof(stackbuf);

    for (size_t i=0; i<2 && bufptr; ++i) {
        va_list args;
        va_start(args, fmt);
        int cx = vsnprintf(bufptr, bufsz, fmt, args);
        va_end(args);

        if ((cx >= 0 && (size_t)cx < bufsz) || cx < 0) {
            line = bufptr;
            break;
        }

        if (bufptr == stackbuf) {
            bufsz = cx + 1;
            bufptr = new (std::nothrow) char[bufsz];

            if (!bufptr) {
                line = "out of memory";
            }
        }
        else {
            line = bufptr;
            break;
        }
    }

    if (line) {
        time_t rawtime;
        struct tm *timeinfo;
        char now[80];

        time (&rawtime);
        timeinfo = localtime(&rawtime);

        strftime(now, sizeof(now), "%d-%m-%Y %H:%M:%S", timeinfo);

        const char *segments[5]{
            "[ ", now, " ] :: ", line, "\x1B[0m\n\n"
        };

        for (const char *segment : segments) {
            size_t len = strlen(segment);

            write(
                STDERR_FILENO, segment,
                len && segment[len-1] == '\n' ? len-1 : len
            );
        }
    }

    if (bufptr && bufptr != stackbuf) delete [] bufptr;
}

static void log(DATABUS::ERROR error, const char *line) noexcept {
    const char *esc = "\x1B[0;31m";

    switch (error) {
        case DATABUS::LIBRARY_ERROR: esc = "\x1B[1;31m"; break;
        case DATABUS::NO_ERROR:      esc = "\x1B[0;32m"; break;
        default: break;
    }

    log("DB: %s%s", esc, line);
}
