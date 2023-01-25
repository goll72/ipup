project('ipup', 'c', version : '0.1', default_options : [
    'warning_level=3',
    'c_std=c11',
])

prefix = get_option('prefix')
sysconfdir = prefix / get_option('sysconfdir')

add_project_arguments('-D_XOPEN_SOURCE=700', language : ['c'])

ldns = dependency('ldns', version : '>=1.7.1')
inih = dependency('inih', version : '>=53')
nl = [
    dependency('libnl-3.0', version : '>=3.4.0'),
    dependency('libnl-route-3.0', version : '>=3.4.0')
]

subdir('src')
subdir('include')

ipup = executable('ipup', [ipup_src, ipup_main, util],
    dependencies : [ldns, inih, nl],
    include_directories : inc,
    install : true)

subdir('tests')
