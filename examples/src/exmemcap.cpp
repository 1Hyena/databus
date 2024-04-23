// SPDX-License-Identifier: MIT
#include "main.h"

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
        DATABUS::ERROR error = databus.set_entry(i, "");

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
