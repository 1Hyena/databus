// SPDX-License-Identifier: MIT
#include "../../databus.h"
#include <cstdlib>

int main(int argc, char **argv) {
    DATABUS databus;

    databus.init();

    databus.set_payload(1, "Hello, World!");

    printf("%s\n", (const char *) databus.get_payload(1).data);

    databus.deinit();

    return EXIT_SUCCESS;
}
