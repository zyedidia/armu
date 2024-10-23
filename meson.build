project(
  'armu',
  ['c'],
  default_options: ['warning_level=1', 'buildtype=debugoptimized'],
  meson_version: '>=0.60.3',
)

disarm = subproject('disarm').get_variable('disarm64')
dynasm = subproject('dynasm').get_variable('dynasm_dep')
minilua = subproject('dynasm').get_variable('minilua')
dynasm_lua = subproject('dynasm').get_variable('dynasm_lua')

cpu_x64 = custom_target(
  'cpu_x64.gen.c',
  output: ['cpu_x64.gen.c'],
  input: files('cpu_x64.c'),
  command: [minilua, dynasm_lua, '-o', '@OUTPUT@', '@INPUT@'],
)

srcs = [
  cpu_x64
]

libarmu = executable(
  'armu',
  sources: srcs,
  dependencies: [disarm.as_link_whole(), dynasm],
  install: true,
)
