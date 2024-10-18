#include <assert.h>

#include "armu.h"
#include "disarm64.h"

#include "cpu.h"

static uint32_t
fetch(struct Armu* armu)
{
    uint32_t* insnp = (uint32_t*) armu->pc;
    return *insnp;
}

void
armu_run(struct Armu* armu)
{
    uint32_t insn = fetch(armu);
    struct Da64Inst dinst;
    da64_decode(insn, &dinst);

    switch (dinst.mnem) {
    case DA64I_ADD_EXT:
        add_ext(armu, &dinst);
        break;
    default:
        assert(!"unknown instruction");
        return;
    }
}
