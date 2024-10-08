// SPDX-License-Identifier: MIT
#include "../../databus.h"
#include "../../utils/log.h"
#include <chrono>
#include <thread>

static void run(DATABUS &);
static void handle(DATABUS &, DATABUS::ALERT &, size_t &cycle);

int main(int argc, char **argv) {
    DATABUS databus;

    databus.set_logger(
        [](DATABUS::ERROR error, const char *line) noexcept {
            log(error, line);
        }
    );

    databus.set_memcap(65536);

    log("%s", "starting the program");

    if (!databus.init()) {
        log("%s", "failed to initialize");

        return EXIT_FAILURE;
    }

    run(databus);

    databus.deinit();

    log("%s", "exiting the program");

    return EXIT_SUCCESS;
}

void run(DATABUS &db) {
    for (size_t i=1; i<=10; ++i) {
        // Let's populate the database with some entries.

        DATABUS::ERROR error = db.set_entry(i, "");

        if (error != DATABUS::NO_ERROR) {
            log("failed to set entry %lu (%s)", i, db.to_string(error));
        }
    }

    size_t cycle = 1;

    while (!db.next_error()) {
        DATABUS::ALERT alert;

        while ((alert = db.next_alert()).valid) {
            handle(db, alert, cycle);
        }

        if (cycle > 3) {
            break;
        }

        if (db.idle()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            db.kick_start();
        }
    }

    if (db.last_error() != DATABUS::NO_ERROR) {
        log("%s", db.to_string(db.last_error()));
    }
}

void handle(DATABUS &db, DATABUS::ALERT &alert, size_t &cycle) {
    log("#%-2lu: %s", alert.entry, db.to_string(alert.event));

    if (alert.event == DATABUS::FINALIZE) {
        log("END OF CYCLE %lu", cycle++);
    }
}
