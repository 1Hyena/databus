// SPDX-License-Identifier: MIT
#include "../../databus.h"

int main(int argc, char **argv) {
    DATABUS databus;

    databus.init();

    databus.set_entry(1, "Hello, World!");

    printf("%s\n", databus.get_entry(1).c_str);

    databus.deinit();

    return EXIT_SUCCESS;
}
