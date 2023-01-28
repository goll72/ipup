if not get_option('tests')
    subdir_done()
endif

criterion = dependency('criterion')

obj_private = ipup.extract_objects(ipup_src)
inc_private = include_directories('..' / 'src')

exe_args = {
    'include_directories' : [inc, inc_private],
    'dependencies' : [criterion, ldns, inih, nl],
    'link_args' : '-Wl,-zmuldefs'
}

foreach basename : ['conf', 'dns', 'map']
    test(basename,
        executable(basename,
            f'test-@basename@.c',
            objects : obj_private,
            kwargs : exe_args),
        args : '--tap', protocol : 'tap')
endforeach
