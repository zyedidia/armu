project('dynasm', 'c', version: 'v2.1')

minilua = executable(
  'minilua',
  sources: files('src/host/minilua.c'),
  link_args: ['-lm'],
  native: true,
  install: false,
)

srcs = files(
  'dynasm/dasm_arm.h',
  'dynasm/dasm_arm64.h',
  'dynasm/dasm_mips.h',
  'dynasm/dasm_ppc.h',
  'dynasm/dasm_proto.h',
  'dynasm/dasm_x86.h',
)

dynasm_dep = declare_dependency(
  sources: srcs,
  include_directories: include_directories('.'),
)

cp = find_program('cp')

dynasm_lua = files('dynasm/dynasm.lua').get(0)
