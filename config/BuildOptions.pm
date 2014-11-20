%BuildOptions = (%BuildOptions,
    NAME                => 'WWW::HKP',
    AUTHOR              => 'David Zurborg <zurborg@cpan.org>',
    VERSION_FROM        => 'lib/WWW/HKP.pm',
    ABSTRACT_FROM       => 'lib/WWW/HKP.pm',
    LICENSE             => 'ISC',
    PL_FILES            => {},
    PMLIBDIRS           => [qw[ lib ]],
    PREREQ_PM => {
        'experimental' => 0,
        'Test::More' => 0,
        'LWP::UserAgent' => 6.05,
        'URI' => 1.60,
        'URI::Escape' => 3.31
    },
    dist => {
        COMPRESS            => 'gzip -9f',
        SUFFIX              => 'gz',
        CI                  => 'git add',
        RCS_LABEL           => 'true',
    },
    clean               => { FILES => 'WWW-HKP-* *~' },
    depend => {
        '$(FIRST_MAKEFILE)' => 'config/BuildOptions.pm',
    },
    META_MERGE => {
        resources => {
            repository => 'https://github.com/zurborg/libwww-hkp-perl',
            homepage   => 'http://development.david-zurb.org/projects/libwww-hkp-perl',
            bugtracker => 'http://development.david-zurb.org/projects/libwww-hkp-perl/issues',
        },
        no_index => {directory => [qw/t/]},
    },
);
