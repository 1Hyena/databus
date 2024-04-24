// SPDX-License-Identifier: MIT
#include "main.h"
#include <chrono>
#include <thread>
#include <string>
#include <array>

static void handle(DATABUS &, DATABUS::ALERT &, size_t);

int main(int argc, char **argv) {
    std::array<std::string, 2> prefix;
    std::array<DATABUS, prefix.size()> databus;

    log("%s", "starting the program");

    for (DATABUS &db : databus) {
        size_t i = static_cast<size_t>(&db - &databus[0]);
        prefix[i].append("DB ").append(std::to_string(i+1)).append(": ");

        db.set_logger(
            [](DATABUS::ERROR error, const char *line, void *udata) noexcept {
                log(error, line, reinterpret_cast<const char*>(udata));
            }, const_cast<char *>(prefix[i].c_str())
        );

        db.set_memcap(65536);

        if (!db.init()) {
            log("%s", "failed to initialize");

            return EXIT_FAILURE;
        }

        if (i == 0) {
            for (size_t i=1; i<=10; ++i) {
                // Let's populate the database with some entries.

                DATABUS::ERROR error = db.set_entry(i, "");

                if (error != DATABUS::NO_ERROR) {
                    log("failed to set entry %lu (%s)", i, db.to_string(error));
                }
            }
        }
    }

    DATABUS::ERROR error{};

    while (!error) {
        for (DATABUS &db : databus) {
            const size_t i = static_cast<size_t>(&db - &databus[0]);
            error = db.next_error();

            if (!error) {
                DATABUS::ALERT alert;

                while ((alert = db.next_alert()).valid) {
                    handle(db, alert, i);
                }

                continue;
            }

            log("%s", db.to_string(error));
            break;
        }

        if (!error) {
            log("tick");
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }

    for (DATABUS &db : databus) {
        db.deinit();
    }

    log("%s", "exiting the program");

    return EXIT_SUCCESS;
}

void handle(DATABUS &db, DATABUS::ALERT &alert, size_t index) {
    log("DB %lu: %lu: %s", index + 1, alert.entry, db.to_string(alert.event));
}
