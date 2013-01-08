package Protocol::OAuth::Client;

use strict;
use warnings;

use URI::Escape qw(uri_escape_utf8);
use Protocol::OAuth::Signature;
use Protocol::OAuth::Util;

sub new {
    my $class = shift;
    $class = ref $class if ref $class;
    my (%params) = @_;

    my $self = {};
    bless $self, $class;

    $self->{request_token_url} = $params{request_token_url};
    $self->{access_token_url}  = $params{access_token_url};
    $self->{authorize_url}     = $params{authorize_url};

    $self->{oauth_consumer_key}     = $params{oauth_consumer_key};
    $self->{oauth_consumer_secret}  = $params{oauth_consumer_secret};
    $self->{oauth_token}            = $params{oauth_token};
    $self->{oauth_token_secret}     = $params{oauth_token_secret};
    $self->{oauth_callback_url}     = $params{oauth_callback_url};
    $self->{oauth_verifier}         = $params{oauth_verifier};
    $self->{oauth_signature_method} = $params{oauth_signature_method};
    $self->{oauth_version}          = $params{oauth_version};

    $self->{realm}   = $params{realm};
    $self->{http_cb} = $params{http_cb};

    die 'http_cb is required' unless $self->{http_cb};

    $self->{oauth_version} ||= '1.0';
    $self->{realm}         ||= 'Protocol::OAuth';

    return $self;
}

sub request_token {
    my $self = shift;
    my ($params) = @_;

    return $self->_make_request('request_token', 'POST',
        $self->{request_token_url}, $params);
}

sub access_token {
    my $self = shift;
    my ($params) = @_;

    return $self->_make_request('access_token', 'POST',
        $self->{access_token_url}, $params);
}

sub request_resource {
    my $self = shift;
    my ($method, $url, $params) = @_;

    return $self->_make_request('request_resource', $method, $url, $params);
}

sub clone {
    my $self = shift;
    my (%params) = @_;

    return $self->new(%{$self}, %params);
}

sub _make_request {
    my $self = shift;
    my ($type, $method, $url, $custom_params) = @_;

    my $params = {};
    $params->{oauth_consumer_key}     = $self->{oauth_consumer_key};
    $params->{oauth_consumer_secret}  = $self->{oauth_consumer_secret};
    $params->{oauth_token}            = $self->{oauth_token};
    $params->{oauth_token_secret}     = $self->{oauth_token_secret};
    $params->{oauth_callback_url}     = $self->{oauth_callback_url};
    $params->{oauth_verifier}         = $self->{oauth_verifier};
    $params->{oauth_signature_method} = $self->{oauth_signature_method};
    $params->{oauth_version}          = $self->{oauth_version};

    # Initialize signature object
    my $signature = Protocol::OAuth::Signature->new(
        url    => $url,
        method => $method,
        %$params
    );

    $custom_params ||= {};

    my $result = $signature->sign(
        {
            oauth_nonce => Protocol::OAuth::Util->generate_hex_string(8, 32),
            oauth_timestamp => time,
            %$custom_params
        }
    );

    my $headers = {
        Authorization => 'OAuth ' . join ',' =>
          map { $_ . '="' . uri_escape_utf8($result->{params}->{$_}) . '"' }
          sort keys %{$result->{params}}
    };

    my $content;
    if (%$custom_params) {
        my $joined_params = join '&', map {
            uri_escape_utf8($_) . '='
              . uri_escape_utf8($custom_params->{$_})
        } keys %$custom_params;

        if ($method eq 'GET') {
            $url .= '?' . $joined_params;
        }
        elsif ($method eq 'POST') {
            $content = $joined_params;
        }
    }

    my $response = $self->{http_cb}->($self, $method, $url, $headers, $content);

    if ($response->{status} && $response->{status} eq '200') {
        my $content = $response->{content};

        my @pairs = split /\&/, $content;
        my %pairs = map {split /=/, $_, 2} @pairs;

        if ($type eq 'request_token' || $type eq 'access_token') {
            use Data::Dumper; warn Dumper(\%pairs);
            die 'Invalid response'
              unless $pairs{oauth_token} && $pairs{oauth_token_secret};

            return \%pairs;
        }
        else {
            return \%pairs;
        }
    }
    else {
        die 'Invalid response';
    }
}

1;
