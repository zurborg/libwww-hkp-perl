use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::HKP',
    AUTHOR              => 'David Zurborg <zurborg@cpan.org>',
    VERSION_FROM        => 'lib/Net/HKP.pm',
    ABSTRACT_FROM       => 'lib/Net/HKP.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'LWP::UserAgent' => 6.05,
        'URI' => 1.60,
        'URI::Escape' => 3.31
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-HKP-*' },
);
