#pragma once

#include <stdint.h>
#include <stdbool.h>

struct Flags {
    bool n;
    bool z;
    bool c;
    bool v;
};

struct Armu {
    uint64_t regs[32];
    uintptr_t pc;
};

void armu_run(struct Armu* armu);
