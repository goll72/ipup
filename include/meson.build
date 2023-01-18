util = configure_file(configuration : {
        'SYSCONFDIR': sysconfdir,
        'VCS_TAG': '@VCS_TAG@'  # silence warning
    }, input : 'util.h.in', output : 'util.h.in')

util = vcs_tag(input : util, output : 'util.h')
