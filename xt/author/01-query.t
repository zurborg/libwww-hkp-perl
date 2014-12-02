#!perl

use Test::More;

require_ok( 'WWW::HKP' );

my $hkp = WWW::HKP->new(host => 'pgp.mit.edu');

my $keys = $hkp->query(index => 'zurborg@cpan.org');
ok $keys;
diag $hkp->error if $hkp->error;

is $hkp->query(index => 'n.o.n.e.x.i.s.t.i.n.g.n.a.m.e@n.o.n.e.x.i.s.t.i.n.g.d.o.m.a.i.n') => undef;

foreach my $keyid (keys %$keys) {
	ok $hkp->query(get => $keyid);
	diag "get $keyid: ".$hkp->error if $hkp->error;
}

done_testing;
