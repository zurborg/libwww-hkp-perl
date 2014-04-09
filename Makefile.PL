use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'WWW::HKP',
    AUTHOR              => 'David Zurborg <zurborg@cpan.org>',
    VERSION_FROM        => 'lib/WWW/HKP.pm',
    ABSTRACT_FROM       => 'lib/WWW/HKP.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'ISC')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
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
    postamble => {
        REDMINE_BASEURL     => 'http://development.david-zurb.org/',
        REDMINE_PROJECT     => 'libwww-hkp-perl',
    },
);

sub MY::postamble {
	my ($MM, %options) = @_;
	return sprintf 'redmine_wiki: $(MAN1PODS) $(MAN3PODS)'
		."\n\t"
		.'pods2redmine --base-url "%s" --project "%s" --version "%s" --with-toc -- $?'
                ,$options{REDMINE_BASEURL}
		,$options{REDMINE_PROJECT}
		,$MM->{VERSION}
	;
}
