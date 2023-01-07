project('ipup', 'c', version : '0.1', default_options : [
    'warning_level=3',
    'c_std=c11',
])

ver = meson.project_version()
add_project_arguments(f'-DVERSION=@ver@', language : 'c')
add_project_arguments('-D_XOPEN_SOURCE=700', language : ['c'])

ldns = dependency('ldns')
inih = dependency('inih')
nl = [dependency('libnl-3.0'), dependency('libnl-route-3.0')]

subdir('src')
executable('ipup', ipup_src,
    dependencies : [ldns, inih, nl],
    include_directories : 'include',
    install : true)
