#include "../../databus.h"
#include <ctime>
#include <cstdlib>
#include <charconv>
#include <array>

inline void log(const char *fmt, ...) noexcept {
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

inline void log(
    DATABUS::ERROR error, const char *line, const char *prefix ="DB: "
) noexcept {
    const char *esc = "\x1B[0;31m";

    switch (error) {
        case DATABUS::LIBRARY_ERROR: esc = "\x1B[1;31m"; break;
        case DATABUS::NO_ERROR:      esc = "\x1B[0;32m"; break;
        default: break;
    }

    log("%s%s%s", prefix, esc, line);
}

inline void log(DATABUS::ERROR error, const char *line, void *udata) noexcept {
    std::array<char, 32> prefix{ 'D', 'B', ' ' };
    const auto res = std::to_chars(
        prefix.data() + 3, prefix.data() + prefix.size() - 2,
        reinterpret_cast<uintptr_t>(udata)
    );

    if (res.ec == std::errc()) {
        res.ptr[0] = ':';
        res.ptr[1] = ' ';
    }
    else prefix[0] = '\0';

    log(error, line, prefix.data());
}
