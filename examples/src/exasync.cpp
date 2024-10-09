// SPDX-License-Identifier: MIT
#include "../../databus.h"
#include "../../utils/log.h"
#include <chrono>
#include <thread>
#include <cinttypes>
#include <span>
#include <bitset>
#include <iostream>
#include <vector>
#include <future>

static void handle(DATABUS &, DATABUS::ALERT &, size_t &);

std::array<std::vector<uint8_t>, 2> ether;
std::mutex ether_mutex;
std::mutex log_mutex;

template<typename... Args>
void mt_log(Args... args) noexcept {
    std::lock_guard<std::mutex> guard(log_mutex);
    log(args...);
}

void mt_log(DATABUS::ERROR error, const char *line, void *udata) noexcept {
    std::lock_guard<std::mutex> guard(log_mutex);
    log(error, line, udata);
}

int work(size_t index, size_t count) {
    DATABUS db;

    db.set_logger(mt_log, reinterpret_cast<void *>(index));
    db.set_memcap(65536);
    db.set_matrix(index, count);

    if (!db.init()) {
        mt_log("%s", "failed to initialize");

        return EXIT_FAILURE;
    }

    if (index == 0) {
        std::array graph{
            5, 5, 6, 6, 7, 7, 0, 0, 8, 8, 9, 9, 10, 10, 1, 1, 3, 3
        };

        for (size_t i=0; i<graph.size(); ++i) {
            // Let's populate the database with some entries.

            DATABUS::ERROR error = db.set_entry(i+1, "");

            if (error != DATABUS::NO_ERROR) {
                mt_log(
                    "failed to set entry %lu (%s)", i+1, db.to_string(error)
                );
            }
        }

        for (size_t i=0; i<graph.size(); ++i) {
            db.set_container(i+1,graph[i]);
        }
    }

    size_t cycle = 1;
    DATABUS::ERROR error{};

    while (!error) {
        error = db.next_error();

        if (error != DATABUS::NO_ERROR) {
            mt_log("%s (DB %lu)", db.to_string(error), index);
            break;
        }

        DATABUS::ALERT alert;

        while ((alert = db.next_alert()).valid) {
            handle(db, alert, cycle);
        }

        if (!db.idle()) {
            continue;
        }

        for (;;) {
            mt_log("DB %lu: waiting", index);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            std::lock_guard<std::mutex> guard(ether_mutex);

            if (ether[index].empty()) {
                continue;
            }

            mt_log("DB %lu: waking", index);
            db.kick_start();

            break;
        }
    }

    db.deinit();

    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    log("%s", "starting the program");

    std::array<std::future<int>, ether.size()> jobs;

    for (size_t i=0; i<jobs.size(); ++i) {
        jobs[i] = std::async(std::launch::async, &work, i, jobs.size());
    }

    for (auto &job : jobs) {
        int result = job.get();

        if (result != EXIT_SUCCESS) {
            log("%s", "exiting the program with error");

            return result;
        }
    }

    log("%s", "exiting the program");

    return EXIT_SUCCESS;
}

void handle(DATABUS &db, DATABUS::ALERT &alert, size_t &cycle) {
    const size_t index = db.get_index();

    mt_log(
        "DB %lu: %s of #%lu/%lu: %s", index, db.to_string(alert.event),
        db.get_container(alert.entry), alert.entry,
        db.get_entry(alert.entry).c_str
    );

    switch (alert.event) {
        case DATABUS::SERIALIZE: {
            const char *str = db.get_entry(alert.entry).c_str;
            std::intmax_t val = std::strtoimax(str, nullptr, 10);

            if (db.next_random() % 2) {
                ++val;
            }

            db.set_entry(alert.entry, std::to_string(val).c_str());

            break;
        }
        case DATABUS::SYNCHRONIZE: {
            const void *outgoing = nullptr;
            size_t length = db.peek(&outgoing);

            std::lock_guard<std::mutex> guard(ether_mutex);

            if (length) {
                for (size_t i=0; i<ether.size(); ++i) {
                    if (i == index) {
                        continue;
                    }

                    ether[i].insert(
                        ether[i].end(), static_cast<const uint8_t*>(outgoing),
                        static_cast<const uint8_t*>(outgoing) + length
                    );
                }

                db.read(nullptr, length);
            }

            if (!ether[index].empty()) {
                size_t capacity = db.reserve(ether[index].size());

                if (capacity) {
                    size_t written = std::min(capacity, ether[index].size());
                    DATABUS::ERROR error = db.write(
                        ether[index].data(), written
                    );

                    if (error != DATABUS::NO_ERROR) {
                        mt_log(
                            "DB %lu: %s (%s:%d)",
                            index, db.to_string(error), __FILE__, __LINE__
                        );
                    }
                    else {
                        ether[index].erase(
                            ether[index].begin(),ether[index].begin()+written
                        );
                    }
                }
            }

            break;
        }
        case DATABUS::FINALIZE: {
            mt_log("DB %lu: END OF CYCLE %lu", index, cycle++);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            db.kick_start();

            break;
        }
        default: break;
    }
}
