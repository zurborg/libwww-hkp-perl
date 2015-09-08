#!perl

use Test::More;

require_ok('WWW::HKP');

my $hkp = WWW::HKP->new( host => 'pgp.mit.edu' );

my $keys = $hkp->query( index => 'zurborg@cpan.org' );
ok $keys;
diag $hkp->error if $hkp->error;

is $hkp->query( index =>
'hgl43hihdlhflkjhdsflkhdslkfhadskhksdhkfiuzrewtiurealkdshfkagdsfkjagdfjgdskfwetr'
) => undef;

foreach my $keyid ( keys %$keys ) {
    ok $hkp->query( get => $keyid );
    diag "get $keyid: " . $hkp->error if $hkp->error;
}

done_testing;
