#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>

#define DA_NOSTRUCT

#include "dynasm/dasm_proto.h"
#include "dynasm/dasm_x86.h"
#include "disarm64.h"

struct A64State {
    uint64_t regs[32];
    void (*trap)(struct A64State*);
};

void trap(struct A64State* state) {
    printf("TRAPPED\n");
    exit(1);
}

typedef void (*jitfn_t)(struct A64State*);

static void* link_and_encode(dasm_State** d, size_t icount) {
    size_t sz;
    void* buf;
    dasm_link(d, &sz);
    buf = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(buf != (void*) -1);

    dasm_encode(d, buf);

    uint64_t* ibuf = (uint64_t*) buf;
    // Write the rebound table
    for (size_t i = 0; i < icount; i++) {
        ibuf[i] = (uint64_t) buf + dasm_getpclabel(d, i);
    }

    mprotect(buf, sz, PROT_READ | PROT_EXEC);
    return buf;
}

enum {
    TMP1 = 5,
    TMP2 = 15,
};

|.arch x64
|.section code

|.globals lbl_

|.actionlist a64_actions

|.define a64_x0, rdi
|.define a64_x1, rsi
|.define a64_x2, rdx
|.define a64_x3, rcx
|.define a64_x4, r8
|.define a64_x5, r9
|.define a64_x21, rax
|.define a64_x30, rbx
|.define a64_x18, r11
|.define a64_x22, r12
|.define a64_x23, r13
|.define a64_x6, r14
|.define tmp2, r15
|.define tmp1, rbp
|.define a64_sp, rsp
|.define a64_state, r10

|.type state, struct A64State, a64_state

static int preg(uint8_t a64_reg, uint8_t tmp) {
    switch (a64_reg) {
    case DA_GP(0):
        return 7; // rdi
    case DA_GP(1):
        return 6; // rsi
    case DA_GP(2):
        return 2; // rdx
    case DA_GP(3):
        return 1; // rcx
    case DA_GP(30):
        return 3; // rbx
    }
    return tmp;
}

static int reg(dasm_State** Dst, uint8_t a64_reg, uint8_t tmp) {
    int r = preg(a64_reg, tmp);
    if (r != tmp)
        return r;
    | mov Rq(tmp), state->regs[a64_reg]
    return tmp;
}

static void regwr(dasm_State** Dst, uint8_t a64_reg, uint8_t tmp) {
    int r = preg(a64_reg, tmp);
    if (r != tmp)
        return;
    | mov state->regs[a64_reg], Rq(tmp)
}

static void movconst(dasm_State** Dst, uint8_t a64_reg, uint64_t uimm, uint8_t tmp) {
    uint8_t x64_reg = preg(a64_reg, tmp);
    if (uimm <= 0xffffffff)
        | mov Rq(x64_reg), uimm
    else
        | mov64 Rq(x64_reg), uimm
    regwr(Dst, a64_reg, tmp);
}

static size_t tolbl(size_t pc, size_t pcstart) {
    return (pc-pcstart)/sizeof(uint32_t);
}

static jitfn_t compile(const char* buf, size_t size, size_t pcstart) {
    dasm_State* d;

    const uint32_t* code = (const uint32_t*) buf;
    size_t n = size / sizeof(uint32_t);

    dasm_init(&d, DASM_MAXSECTION);

    void* labels[lbl__MAX];
    dasm_setupglobal(&d, labels, lbl__MAX);

    dasm_setup(&d, a64_actions);
    dasm_growpc(&d, n);

    dasm_State** Dst = &d;
    |.code
    |->rbt:

    // rebound table
    for (size_t pcinst = 0; pcinst < n; pcinst++) {
        // emit a zero word that will be filled in after encoding
        | .byte 0x00, 0x000, 0x000, 0x00, 0x00, 0x00, 0x00, 0x00
    }

    |->entry:
    | mov a64_state, rdi
    | mov rdi, 0
    for (size_t pcinst = 0; pcinst < n; pcinst++) {
        size_t pc = pcstart + pcinst * sizeof(uint32_t);
        struct Da64Inst inst;
        |=>pcinst:
        da64_decode(code[pcinst], &inst);
        assert(inst.mnem != DA64I_UNKNOWN);
        switch (inst.mnem) {
        case DA64I_BRK:
            | int3
            break;
        case DA64I_UDF:
            | mov rdi, a64_state
            | jmp aword state->trap
            break;
        case DA64I_MOVZ:
            assert(inst.ops[1].type == DA_OP_UIMMSHIFT);
            uint64_t uimm = inst.ops[1].uimm16 << inst.ops[1].immshift.shift;
            movconst(Dst, inst.ops[0].reg, uimm, TMP1);
            break;
        case DA64I_ADR:
            movconst(Dst, inst.ops[0].reg, pc+inst.imm64, TMP1);
            break;
        case DA64I_STR_IMM:
            | mov [Rq(reg(Dst, inst.ops[1].reg, TMP1))+inst.ops[1].uimm16], Rq(reg(Dst, inst.ops[0].reg, TMP2))
            break;
        case DA64I_LDR_IMM:
            | mov Rq(reg(Dst, inst.ops[0].reg, TMP2)), [Rq(reg(Dst, inst.ops[1].reg, TMP1))]
            regwr(Dst, inst.ops[0].reg, TMP1);
            break;
        case DA64I_B:
            | jmp =>tolbl(pc+inst.imm64, pcstart)
            break;
        case DA64I_BL:
            movconst(Dst, 30, pc+4, TMP1);
            | jmp =>tolbl(pc+inst.imm64, pcstart);
            break;
        case DA64I_BR:
            | lea tmp2, [->rbt]
            | jmp aword [tmp2+Rq(reg(Dst, inst.ops[0].reg, TMP1))*2-pcstart*2]
            break;
        case DA64I_RET:
            | lea tmp2, [->rbt]
            | jmp aword [tmp2+Rq(reg(Dst, inst.ops[0].reg, TMP1))*2-pcstart*2]
            break;
        case DA64I_BLR:
            movconst(Dst, 30, pc+4, TMP1);
            | lea tmp2, [->rbt]
            | jmp aword [tmp2+Rq(reg(Dst, inst.ops[0].reg, TMP1))*2-pcstart*2]
            break;
        default:
            fprintf(stderr, "unhandled: 0x%x\n", inst.mnem);
            return NULL;
        }
    }
    link_and_encode(&d, n);
    dasm_free(&d);
    return (jitfn_t) labels[lbl_entry];
}

static void run(const char* program, size_t size) {
    struct A64State state;
    state.trap = trap;
    compile(program, size, 0x410000)(&state);
}

int main(int argc, char** argv) {
    if(argc == 2) {
        long sz;
        char* program;
        FILE* f = fopen(argv[1], "r");
        if(!f) {
            fprintf(stderr, "Cannot open %s\n", argv[1]);
            return 1;
        }
        fseek(f, 0, SEEK_END);
        sz = ftell(f);
        program = mmap((void*) 0x410000, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fileno(f), 0);
        assert(program != (void*) -1);
        fclose(f);
        run(program, sz);
        return 0;
    } else {
        fprintf(stderr, "Usage: %s INFILE.bin\n", argv[0]);
        return 1;
    }
}
