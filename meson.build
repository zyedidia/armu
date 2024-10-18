project(
  'armu',
  ['c'],
  default_options: ['warning_level=3', 'buildtype=release'],
  meson_version: '>=0.60.3',
)

disarm = subproject('disarm').get_variable('disarm64')

srcs = [
  'armu.c',
]

libarmu = static_library(
  'armu',
  srcs,
  dependencies: [disarm.as_link_whole()],
  install: true,
)

armu = executable(
  'armu',
  files('main.c'),
  link_with: [libarmu],
  install: true,
)
