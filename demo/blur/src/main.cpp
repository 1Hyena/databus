// SPDX-License-Identifier: MIT

#include "../../../databus.h"
#include "../../../utils/image.h"
#include "../../../utils/log.h"
#include <chrono>
#include <thread>
#include <cinttypes>
#include <span>
#include <bitset>
#include <iostream>
#include <vector>
#include <future>
#include <fstream>
#include <cmath>

DATABUS::EVENT handle(
    DATABUS &, DATABUS::ALERT &,
    std::vector<unsigned char> &, std::vector<unsigned char> &
);
template<typename... Args>
void mt_log(Args... args) noexcept;
void mt_log(DATABUS::ERROR error, const char *line, void *udata) noexcept;
int work(size_t index, size_t count);

struct global_type {
    size_t image_width;
    size_t image_height;
    std::vector<unsigned char> *image;
} global;

std::array<std::vector<uint8_t>, 2> ether;
std::mutex ether_mutex;
std::mutex log_mutex;

int main(int argc, char *argv[]) {
    if (argc != 3) {
        abort();
    }

    std::ifstream fin(argv[1], std::ios::binary);
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(fin), {});
    fin.close();

    std::vector<unsigned char> rgba;
    const auto load_info = load_png(buffer.data(), buffer.size(), &rgba);

    if (rgba.empty()) {
        log(
            "failed to load %s (%s:%d)", argv[1], load_info.file, load_info.line
        );

        return EXIT_FAILURE;
    }

    log(
        "loaded %s (%lux%lu, size %lu)",
        argv[1], load_info.w, load_info.h, buffer.size()
    );

    global.image_width = load_info.w;
    global.image_height = load_info.h;
    global.image = &rgba;

    std::array<std::future<int>, ether.size()> jobs;

    for (size_t i=0; i<jobs.size(); ++i) {
        jobs[i] = std::async(std::launch::async, &work, i, jobs.size());
    }

    for (auto &job : jobs) {
        int result = job.get();

        if (result != EXIT_SUCCESS) {
            log("DB %lu: ended with an error", &job - &jobs.front());
            abort();
        }
    }

    log(
        "raw bitmap checksum is %u",
        unsigned(DATABUS::crc16(0, rgba.data(), rgba.size()))
    );

    buffer.clear();
    const auto save_info = save_png(buffer, rgba, load_info.w);

    if (!save_info.written) {
        log(
            "failed to save %s (%s:%d)", argv[2], save_info.file, save_info.line
        );

        return EXIT_FAILURE;
    }

    if (buffer.empty()) {
        return EXIT_FAILURE;
    }

    log("saving %s (size %lu)", argv[2], buffer.size());

    std::ofstream fout(argv[2], std::fstream::trunc|std::fstream::binary);
    fout.write(reinterpret_cast<char *>(buffer.data()), buffer.size());
    fout.close();

    return EXIT_SUCCESS;
}

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
    std::vector<unsigned char> foreground(*global.image);
    std::vector<unsigned char> background(*global.image);
    DATABUS db;

    db.set_logger(mt_log, reinterpret_cast<void *>(index));
    db.set_memcap(4 * 1024 * 1024);
    db.set_matrix(index + 1, count);

    if (!db.init()) {
        mt_log("%s", "failed to initialize");

        return EXIT_FAILURE;
    }

    if (global.image->size() != global.image_width*global.image_height*4) {
        mt_log("%s", "image size does not match its resolution");

        return EXIT_FAILURE;
    }

    const size_t band_height = global.image_height / count;
    const size_t start_y = index * band_height;
    const size_t end_y{
         index + 1 == count ? global.image_height : start_y + band_height
    };

    size_t next_id = 1 + start_y * global.image_width;

    for (size_t y=start_y; y<end_y; ++y) {
        for (size_t x=0; x<global.image_width; ++x) {
            unsigned char *rgba{
                global.image->data() + (y * global.image_width * 4) + x * 4
            };

            DATABUS::ERROR error = db.set_entry(next_id, rgba, 4);

            if (error != DATABUS::NO_ERROR) {
                mt_log(
                    "failed to set entry %lu (%s)",
                    next_id, db.to_string(error)
                );
            }

            ++next_id;
        }
    }


    DATABUS::ERROR error{};
    bool shutdown = false;
    size_t iteration = 1;

    while (!error) {
        error = db.next_error();

        if (error != DATABUS::NO_ERROR) {
            mt_log("%s (DB %lu)", db.to_string(error), index);
            break;
        }

        DATABUS::ALERT alert;

        while ((alert = db.next_alert()).valid) {
            DATABUS::EVENT ev = handle(db, alert, foreground, background);

            if (ev == DATABUS::FINALIZE) {
                if (++iteration >= 100) {
                    shutdown = true;
                }
                else {
                    db.kick_start();

                    background = foreground;
                }
            }
        }

        if (shutdown) {
            if (index == 0) {
                global.image->swap(foreground);
            }

            break;
        }

        if (!db.idle()) {
            continue;
        }

        for (;;) {
            std::this_thread::yield();
            std::lock_guard<std::mutex> guard(ether_mutex);

            if (ether[index].empty()) {
                continue;
            }

            db.kick_start();

            break;
        }
    }

    db.deinit();

    return EXIT_SUCCESS;
}

std::array<unsigned char, 4> get_pixel(DATABUS &db, size_t x, size_t y) {
    const size_t id = 1 + y * global.image_width + x;

    const unsigned char *data{
        static_cast<const unsigned char *>(db.get_entry(id).data)
    };

    return { data[0], data[1], data[2], data[3] };
}

std::array<unsigned char, 4> get_pixel(
    std::vector<unsigned char> &rgba, size_t x, size_t y
) {
    const size_t pos = y * global.image_width * 4 + x * 4;
    const unsigned char *data{
        static_cast<const unsigned char *>(rgba.data() + pos)
    };

    return { data[0], data[1], data[2], data[3] };
}

void set_pixel(
    std::vector<unsigned char> &rgba, size_t x, size_t y,
    unsigned char r, unsigned char g, unsigned char b, unsigned char a
) {
    const size_t pos = y * global.image_width * 4 + x * 4;
    unsigned char *data{
        static_cast<unsigned char *>(rgba.data() + pos)
    };

    data[0] = r;
    data[1] = g;
    data[2] = b;
    data[3] = a;
}

DATABUS::EVENT handle(
    DATABUS &db, DATABUS::ALERT &alert, std::vector<unsigned char> &foreground,
    std::vector<unsigned char> &background
) {
    const size_t index = db.get_id() - 1;
    const size_t y = alert.entry ? ((alert.entry - 1) / global.image_width) : 0;
    const size_t x = alert.entry ? ((alert.entry - 1) % global.image_width) : 0;

    switch (alert.event) {
        case DATABUS::SERIALIZE: {
            std::array<double, 4> pixel{};
            std::vector<std::array<unsigned char, 4>> hood;

            hood.emplace_back(get_pixel(background, x, y));

            if (x + 1 < global.image_width) {
                hood.emplace_back(get_pixel(background, x + 1, y));
            }

            if (y + 1 < global.image_height) {
                hood.emplace_back(get_pixel(background, x, y + 1));
            }

            if (x > 0) {
                hood.emplace_back(get_pixel(background, x - 1, y));
            }

            if (y > 0) {
                hood.emplace_back(get_pixel(background, x, y - 1));
            }

            if (x + 1 < global.image_width
            &&  y + 1 < global.image_height) {
                hood.emplace_back(get_pixel(background, x + 1, y + 1));
            }

            if (x > 0 && y + 1 < global.image_height) {
                hood.emplace_back(get_pixel(background, x - 1, y + 1));
            }

            if (x > 0 && y > 0) {
                hood.emplace_back(get_pixel(background, x - 1, y - 1));
            }

            if (y > 0 && x + 1 < global.image_width) {
                hood.emplace_back(get_pixel(background, x + 1, y - 1));
            }

            std::array<unsigned char, 4> rgba;

            for (const auto &px : hood) {
                for (size_t i=0; i<px.size(); ++i) {
                    pixel[i] += double(px[i]) * (1.0 / double(hood.size()));
                }
            }

            for (size_t i=0; i<pixel.size(); ++i) {
                double c = pixel[i];

                rgba[i] = (
                    c < 0.0   ? 0   :
                    c > 255.0 ? 255 : static_cast<unsigned char>(
                        std::round(c)
                    )
                );
            }

            db.set_entry(alert.entry, rgba.data(), rgba.size());

            [[fallthrough]];
        }
        case DATABUS::DESERIALIZE: {
            const unsigned char *data{
                static_cast<const unsigned char *>(
                    db.get_entry(alert.entry).data
                )
            };

            set_pixel(foreground, x, y, data[0], data[1], data[2], data[3]);

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
            break;
        }
        default: break;
    }

    return alert.event;
}
