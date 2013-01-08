package Protocol::OAuth::Signature;

use strict;
use warnings;

use URI::Escape qw(uri_escape_utf8);
use MIME::Base64 qw(encode_base64);
use Digest::HMAC_SHA1 qw(hmac_sha1_hex);

sub new {
    my $class = shift;
    my (%params) = @_;

    my $self = {};
    bless $self, $class;

    $self->{method} = $params{method};
    $self->{url}    = $params{url};

    $self->{oauth_consumer_key}     = $params{oauth_consumer_key};
    $self->{oauth_consumer_secret}  = $params{oauth_consumer_secret};
    $self->{oauth_token}            = $params{oauth_token};
    $self->{oauth_token_secret}     = $params{oauth_token_secret};
    $self->{oauth_signature_method} = $params{oauth_signature_method};

    die 'url required'                   unless $self->{url};
    die 'oauth_consumer_secret required' unless $self->{oauth_consumer_secret};
    die 'oauth_token_secret required'
      if $self->{oauth_token} && !$self->{oauth_token_secret};

    $self->{method}                 ||= 'POST';
    $self->{oauth_signature_method} ||= 'HMAC-SHA1';

    return $self;
}

sub sign {
    my $self = shift;
    my ($params) = @_;

    my $clone = {%$params};

    $clone->{oauth_consumer_key} ||= $self->{oauth_consumer_key};
    $clone->{oauth_token} ||= $self->{oauth_token} if $self->{oauth_token};
    $clone->{oauth_signature_method} ||= $self->{oauth_signature_method};

    my $base_string = $self->_build_base_string($clone);
    my $signing_key = $self->_build_signing_key;
    my $signature   = $self->_sign_params($base_string, $signing_key, $clone);

    $clone->{oauth_signature} = $signature;

    my $result = {};
    $result->{base_string} = $base_string;
    $result->{signing_key} = $signing_key;
    $result->{signature}   = $signature;

    foreach my $key (keys %$clone) {
        delete $clone->{$key} unless $key =~ m/^oauth_/;
    }

    $result->{params} = $clone;

    return $result;
}

sub _build_base_string {
    my $self = shift;
    my ($params) = @_;

    my @values;

    # Add request method
    push @values, uc $self->{method};

    # Add url
    my $url = $self->{url};
    $url = "http://$url" unless $url =~ m{^https?://};
    $url =~ s{\?.*$}{}g;
    push @values, uri_escape_utf8($url);

    # Add params
    delete $params->{oauth_signature};
    delete $params->{realm};

    # Preparing pairs
    my @pairs;
    foreach my $key (keys %$params) {
        my $values = $params->{$key};
        next unless defined $values;

        $values = [$values] unless ref $values eq 'ARRAY';

        foreach my $v (@$values) {
            $key = uri_escape_utf8($key);
            $v   = uri_escape_utf8($v);
            push @pairs, [$key, $v];
        }
    }

    # Sorting pairs (first by name, then by value)
    @pairs = sort { $a->[0] cmp $b->[0] || $a->[1] cmp $b->[1] } @pairs;

    # Concatenating pairs
    my $pairs = join '&' => map { join '=' => @$_ } @pairs;

    push @values, uri_escape_utf8($pairs);

    return join '&' => @values;
}

sub _build_signing_key {
    my $self = shift;

    return uri_escape_utf8($self->{oauth_consumer_secret}) . '&'
      . uri_escape_utf8($self->{oauth_token_secret});
}

sub _sign_params {
    my $self = shift;
    my ($base_string, $signing_key, $params) = @_;

    my $signature_method = $params->{oauth_signature_method}
      || $self->{oauth_signature_method};

    if ($signature_method eq 'PLAINTEXT') {
        return $signing_key;
    }
    else {
        my $digest = '';
        if ($signature_method eq 'HMAC-SHA1') {
            $digest = hmac_sha1_hex($base_string, $signing_key);
        }

        die 'Unsupported signature method: ' . $signature_method
          unless $digest;

        my $base64 = encode_base64(pack('H*', $digest));

        $base64 =~ s{\s*}{}g;

        return $base64;
    }
}

1;
