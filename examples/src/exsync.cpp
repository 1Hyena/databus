// SPDX-License-Identifier: MIT
#include "../../databus.h"
#include "../../utils/log.h"
#include <chrono>
#include <thread>
#include <cinttypes>
#include <span>
#include <bitset>
#include <iostream>

static void handle(DATABUS &, DATABUS::ALERT &, std::span<DATABUS> peers);

int main(int argc, char **argv) {
    std::array<DATABUS, 2> databus;

    log("%s", "starting the program");

    for (DATABUS &db : databus) {
        size_t index = static_cast<size_t>(&db - &databus[0]);

        db.set_logger(log, reinterpret_cast<void *>(index));
        db.set_memcap(65536);
        db.set_matrix(index + 1, databus.size());

        if (!db.init()) {
            log("%s", "failed to initialize");

            return EXIT_FAILURE;
        }

        if (index) {
            continue;
        }

        std::array graph{
            5, 5, 6, 6, 7, 7, 0, 0, 8, 8, 9, 9, 10, 10, 1, 1, 3, 3
        };

        for (size_t i=0; i<graph.size(); ++i) {
            // Let's populate the database with some entries.

            DATABUS::ERROR error = db.set_entry(i+1, "");

            if (error != DATABUS::NO_ERROR) {
                log("failed to set entry %lu (%s)", i+1, db.to_string(error));
            }
        }

        for (size_t i=0; i<graph.size(); ++i) {
            db.set_container(i+1,graph[i]);
        }
    }

    size_t cycle = 1;
    DATABUS::ERROR error{};

    while (!error) {
        size_t idle = 0;

        for (DATABUS &db : databus) {
            error = db.next_error();

            if (!error) {
                DATABUS::ALERT alert;

                while ((alert = db.next_alert()).valid) {
                    handle(db, alert, databus);
                }

                idle += db.idle();

                continue;
            }

            log("%s (DB %lu)", db.to_string(error), &db - &databus.front());
            break;
        }

        if (!error && idle == databus.size()) {
            log("END OF CYCLE %lu", cycle++);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));

            for (DATABUS &db : databus) {
                db.kick_start();
            }
        }
    }

    for (DATABUS &db : databus) {
        db.deinit();
    }

    log("%s", "exiting the program");

    return EXIT_SUCCESS;
}

void handle(DATABUS &db, DATABUS::ALERT &alert, std::span<DATABUS> peers) {
    const size_t index = &db - &peers.front();

    if (alert.entry) {
        log(
            "DB %lu: %s of #%lu/%lu: %s", index, db.to_string(alert.event),
            db.get_container(alert.entry), alert.entry,
            db.get_entry(alert.entry).c_str
        );
    }
    else {
        log("DB %lu: %s", index, db.to_string(alert.event));
    }

    switch (alert.event) {
        case DATABUS::SERIALIZE: {
            const char *str = db.get_entry(alert.entry).c_str;
            std::intmax_t val = std::strtoimax(str, nullptr, 10);

            if (db.next_random() % 2) {
                ++val;

                for (size_t i=0;;++i) {
                    size_t content_id = db.get_content(alert.entry, i);

                    if (!content_id) {
                        break;
                    }

                    if (db.next_random() % 2) {
                        log(
                            "DB %lu: #%lu resets #%lu",
                            index, alert.entry, content_id
                        );

                        db.set_entry(content_id, "0");
                    }
                }
            }

            db.set_entry(alert.entry, std::to_string(val).c_str());

            break;
        }
        case DATABUS::SYNCHRONIZE: {
            const void *outgoing = nullptr;
            size_t length = db.peek(&outgoing);

            for (DATABUS &peer : peers) {
                if (&peer == &db) {
                    continue;
                }

                length = std::min(length, peer.reserve(length));
            }

            if (length) {
                for (DATABUS &peer : peers) {
                    if (&peer == &db) {
                        continue;
                    }

                    const size_t peer_index = &peer - &peers.front();
                    DATABUS::ERROR error = peer.write(outgoing, length);

                    if (error != DATABUS::NO_ERROR) {
                        log(
                            "DB %lu: %s (%s:%d)",
                            peer_index, db.to_string(error), __FILE__, __LINE__
                        );
                    }
                }

                db.read(nullptr, length);
            }

            break;
        }
        default: break;
    }
}
