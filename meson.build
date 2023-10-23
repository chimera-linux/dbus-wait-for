project(
    'dbus-wait-for',
    ['c'],
    version: '0.1',
    default_options: [
        'c_std=c99',
        'warning_level=3',
        'buildtype=debugoptimized',
    ]
)

executable(
    'dbus-wait-for',
    'dbus-wait-for.c',
    install: true,
    dependencies: [dependency('dbus-1')],
)
