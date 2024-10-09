// SPDX-License-Identifier: MIT
#include "../../databus.h"
#include "../../utils/log.h"

int main(int argc, char **argv) {
    log("%s", "starting the program");

    {
        DATABUS databus;

        databus.set_logger(
            [](DATABUS::ERROR error, const char *line) noexcept {
                log(error, line);
            }
        );

        if (!databus.init()) {
            log("%s", "failed to initialize");
        }

        // We deliberately "forget" to call DATABUS::deinit to have a warning
        // logged about this.

        // databus.deinit();
    }

    log("%s", "exiting the program");

    return EXIT_FAILURE;
}
