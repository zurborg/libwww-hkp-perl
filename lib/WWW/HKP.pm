use strict;
use warnings;

package WWW::HKP;

# ABSTRACT: Interface to HTTP Keyserver Protocol (HKP)

use AnyEvent::HTTP qw(http_get http_post);
use Carp;
use URI 1.60;
use URI::Escape 3.31;

# VERSION

=head1 SYNOPSIS

    use WWW::HKP;
    
    my $hkp = WWW::HKP->new();
    
    $hkp->query(index => 'foo@bar.baz');
    $hkp->query(get => 'DEADBEEF');

=head1 DESCRIPTION

This module implements the IETF draft of the OpenPGP HTTP Keyserver Protocol.

More information about HKP is available at L<http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00>.

=method new([%options])

The C<new()> constructor method instantiates a new C<WWW::HKP> object. The following example shows available options and its default values.

	my $hkp = WWW::HKP->new(
		host => 'localhost',
		port => 11371
	);

In most cases you just need to set the I<host> parameter:

	my $hkp = WWW::HKP->new(host => 'pool.sks-keyservers.net');

=cut

sub new {
    my ( $class, %options ) = @_;

    my $uri = URI->new('http:');
    $uri->host( $options{host} || 'localhost' );
    $uri->port( $options{port} || 11371 );

    my $ua = $AnyEvent::HTTP::USERAGENT;
    {
        local $_ = __PACKAGE__ . '/' . $VERSION;
        $ua =~ s{\)$}{ +$_)};
    }

    my $self = {
        ua  => $ua,
        uri => $uri,
    };

    return bless $self => ( ref $class || $class );
}

sub _ua  { shift->{ua} }
sub _uri { shift->{uri} }

sub _get {
    my ( $self, %query ) = @_;
    $self->{error} = undef;
    $self->_uri->path('/pks/lookup');
    $self->_uri->query_form(%query);

    my $cv = AE::cv;
    http_get $self->_uri, sub {
        my ( $body, $hdr ) = @_;
        if ( $hdr->{Status} ne '200' ) {
            $self->{error} = sprintf 'HTTP %d: %s', $hdr->{Status},
              $hdr->{Reason};
            $cv->send;
        }
        else {
            $cv->send($body);
        }
    };
    $cv->recv;
}

sub _post {
    my ( $self, %query ) = @_;
    $self->{error} = undef;
    $self->_uri->path('/pks/lookup');
    my $response = $self->_ua->post( $self->_uri, \%query );
    if (    defined $response
        and ref $response
        and $response->isa('HTTP::Response')
        and $response->is_success )
    {
        return $response->decoded_content;
    }
    else {
        $self->{error} = $response->status_line;
        return;
    }

    my $cv = AE::cv;
    http_post $self->_uri, \%query, (), sub {
        my ( $body, $hdr ) = @_;
        if ( $hdr->{Status} ne '200' ) {
            $self->{error} = sprintf 'HTTP %d: %s', $hdr->{Status},
              $hdr->{Reason};
            $cv->send;
        }
        else {
            $cv->send($body);
        }
    };
    $cv->recv;
}

sub _parse_mr {
    my ( $self, $lines, $filter_ok ) = @_;
    my $keys = {};
    my $key;
    my ( $keyc, $keyn ) = ( 0, 0 );
    foreach my $line ( split /\r?\n/ => $lines ) {
        if ( $line =~ /^info:(\d+):(\d+)$/ ) {
            croak "unsupported hkp version: v$1" unless $1 == 1;
            $keyc = $2;
        }
        elsif ( $line =~
            /^pub:([0-9a-f]{8,16}):(\d*):(\d*):(\d*):(\d*):([der]*)$/i )
        {
            $key = $1;
            $keyn++;
            my ( $algo, $keylen, $created, $expires, $flags, $ok ) =
              ( $2, $3, $4, $5, $6, undef );
            $ok = (
                (
                         ( $created and $created > time )
                      or ( $expires and $expires < time )
                      or ( length $flags )
                ) ? 0 : 1
            );
            if ( $filter_ok and !$ok ) {
                $key = undef;
                next;
            }
            $keys->{$key} = {
                algo    => $algo,
                keylen  => $keylen,
                created => $created || undef,
                expires => $expires || undef,
                revoked => ( $flags =~ /r/ ? 1 : 0 ),
                expired => ( $flags =~ /e/ ? 1 : 0 ),
                deleted => ( $flags =~ /d/ ? 1 : 0 ),
                ok      => $ok,
                uids    => []
            };
        }
        elsif ( $line =~ /^uid:([^:]*):(\d*):(\d*):([der]*)$/i ) {
            next unless defined $key;
            my ( $uid, $created, $expires, $flags, $ok ) =
              ( $1, $2, $3, $4, undef );
            $ok = (
                (
                         ( $created and $created > time )
                      or ( $expires and $expires < time )
                      or ( length $flags )
                ) ? 0 : 1
            );
            next if $filter_ok and !$ok;
            push @{ $keys->{$key}->{uids} } => {
                uid     => uri_unescape($uid),
                created => $created || undef,
                expires => $expires || undef,
                revoked => ( $flags =~ /r/ ? 1 : 0 ),
                expired => ( $flags =~ /e/ ? 1 : 0 ),
                deleted => ( $flags =~ /d/ ? 1 : 0 ),
                ok      => $ok
            };
        }
        else {
            carp "unknown line: $line";
        }
    }
    carp "server said there where $keyc keys, but $keyn keys parsed"
      unless $keyc == $keyn;
    return $keys;
}

=method query($type => $search [, %options ])

The C<query()> method implements both query operations of HKP: I<index> and I<get>

=cut

sub query {
    my ( $self, $type, $search, %options ) = @_;

=head3 I<index> operation

    $hkp->query(index => 'foo@bar.baz');

The first parameter must be I<index>, the secondend parameter an email-address or key-id.

If any keys where found, a hashref is returned. Otherwise C<undef> is returned, an error message can be fetched with C<< $hkp->error() >>.

The returned hashref may look like this:

    {
		'DEADBEEF' => {
			'algo' => '1',
			'keylen' => '2048',
			'created' => '1253025510',
			'expires' => '1399901151',
			'deleted' => 0,
			'expired' => 0,
			'revoked' => 0,
			'ok' => 1,
			'uids' => [
				{
					'uid' => 'Lorem Ipsum (This is an example) <foo@bar.baz>'
					'created' => '1253025510',
					'expires' => '1399901151',
					'deleted' => 0,
					'expired' => 0,
					'revoked' => 0,
					'ok' => 1
				}
			]
		}
    }

The keys of the hashref are key-ids. The meaning of the hash keys in the second level:

=over

=item I<algo>

The algorithm of the key. The values are described in RFC 2440.

=item I<keylen>

The key length in bytes.

=item I<created>

Creation date of the key, in seconds since 1970-01-01 UTC.

=item I<expires>

Expiration date of the key.

=item I<deleted>, I<expired>, I<revoked>

Indication details, whether the key is deleted, expired or revoked. If the flag is that, the value is C<1>, otherwise C<0>.

=item I<ok>

The creation date and expiration date is checked against C<time()>. If it doesn't match or any of the flags above are set, I<ok> will be C<0>, otherwise C<1>.

=item I<uids>

A arrayref of user-ids.

=over

=item I<uid>

The user-id in common format. It can be parsed by L<Email::Address> for example.

=item I<created>, I<expires>, I<deleted>, I<expired>, I<revoked>, I<ok>

This fields have the same meaning as described above. The information is taken from the self-signature, if any. I<created> and I<expired> may be C<undef> if not available (e.g. empty string).

=back

=back

=head4 Available options

=over

=item I<exact>

Set the I<filter_ok> parameter to C<1> (or any expression that evaluates to true), if you want an exact match of your search expression.

=item I<filter_ok>

Set the I<filter_ok> parameter to C<1> (or any expression that evaluates to true), if you want only valid results. All keys or user IDs having I<ok>-parameter of C<0> are ignored.

    $hkp->query(index => 'foo@bar.baz', filter_ok => 1);

=back

=cut

    if ( $type eq 'index' ) {
        my @options = qw(mr);
        push @options => 'exact' if $options{exact};
        my $message = $self->_get(
            op      => 'index',
            options => join( ',' => @options ),
            search  => $search
        );
        return unless defined $message;
        return $self->_parse_mr( $message, $options{filter_ok} ? 1 : 0 );
    }

=head3 I<get> operation

    $hkp->query(get => 'DEADBEEF');

The operation returns the public key of specified key-id or undef, if not found. Any error messages can be fetched with C<< $hkp->error() >>.

=cut

    elsif ( $type eq 'get' ) {
        if ( $search !~ /^0x/ ) {
            $search = '0x' . $search;
        }
        my $message =
          $self->_get( op => 'get', options => 'exact', search => $search );
        return unless defined $message;
        return $message;
    }

=head3 unimplemented operations

A HKP server may implement various other operations. Unimplemented operation cause the module to die with a stack trace.

=cut

    else {
        confess "unknown query type '$type'";
    }
}

=method submit

Submit one or more ASCII-armored version of public keys to the server.

    $pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...";
    
    $hkp->submit($pubkey);
    
    @pubkeys = ($pubkey1, $pubkey2, ...);
    
    $hkp->submit(@pubkeys);

In case of success, C<1> is returned. Otherweise C<0> and an error message can be fetched from C<< $hkp->error() >>.

=cut

sub submit {
    my ( $self, @keys ) = @_;
    my $status = $self->_post( map { ( keytext => $_ ) } @keys );
    return ( defined $status and $status ? 1 : 0 );
}

=method error

Returns last error message, if any.

    $hkp->error; # "404 Not found", for example.

=cut

sub error { shift->{error} }

1;
