package SignatureTest;

use strict;
use warnings;
use utf8;

use base 'TestBase';

use Test::More;
use Test::Fatal;

use Protocol::OAuth::Signature;

sub sign_request_token : Test {
    my $self = shift;

    my $sig = Protocol::OAuth::Signature->new(
        url             => 'https://api.twitter.com/oauth/request_token',
        oauth_consumer_key    => 'GDdmIQH6jhtmLUypg82g',
        oauth_consumer_secret => 'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98'
    );

    my $result = $sig->sign(
        {
            oauth_callback =>
'http://localhost:3005/the_dance/process_callback?service_provider_id=11',
            #oauth_signature_method => 'HMAC-SHA1',
            oauth_nonce     => 'QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk',
            oauth_timestamp => '1272323042',
            oauth_version   => '1.0',
            realm           => 'Perl'
        }
    );

    is_deeply(
        $result,
        {
            base_string =>
'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token&oauth_callback%3Dhttp%253A%252F%252Flocalhost%253A3005%252Fthe_dance%252Fprocess_callback%253Fservice_provider_id%253D11%26oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3DQP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1272323042%26oauth_version%3D1.0',
            signing_key => 'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98&',
            signature   => '8wUi7m5HFQy76nowoCThusfgB+Q=',
            params      => {
                'oauth_signature'    => '8wUi7m5HFQy76nowoCThusfgB+Q=',
                'oauth_timestamp'    => '1272323042',
                'oauth_consumer_key' => 'GDdmIQH6jhtmLUypg82g',
                'oauth_callback' =>
'http://localhost:3005/the_dance/process_callback?service_provider_id=11',
                'oauth_nonce' => 'QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk',
                'oauth_version'          => '1.0',
                'oauth_signature_method' => 'HMAC-SHA1'
            },
        }
    );
}

sub test_access_token : Test {
    my $self = shift;

    my $sig = Protocol::OAuth::Signature->new(
        url             => 'https://api.twitter.com/oauth/access_token',
        oauth_consumer_secret => 'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98',
        oauth_token_secret    => 'x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA',
    );
    my $result = $sig->sign(
        {
            oauth_consumer_key => 'GDdmIQH6jhtmLUypg82g',
            oauth_token        => '8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc',
            oauth_signature_method => 'HMAC-SHA1',
            oauth_nonce     => '9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8',
            oauth_timestamp => '1272323047',
            oauth_verifier  => 'pDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY',
            oauth_version   => '1.0'
        }
    );

    is_deeply(
        $result,
        {
            base_string =>
'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Faccess_token&oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3D9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1272323047%26oauth_token%3D8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc%26oauth_verifier%3DpDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY%26oauth_version%3D1.0',
            signing_key =>
'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98&x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA',
            signature => 'PUw/dHA4fnlJYM6RhXk5IU/0fCc=',
            params    => {
                oauth_consumer_key => 'GDdmIQH6jhtmLUypg82g',
                oauth_token => '8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc',
                oauth_signature_method => 'HMAC-SHA1',
                oauth_nonce     => '9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8',
                oauth_timestamp => '1272323047',
                oauth_verifier => 'pDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY',
                oauth_version  => '1.0',
                oauth_signature => 'PUw/dHA4fnlJYM6RhXk5IU/0fCc=',
            }
        }
    );
}

sub test_custom_params : Test {
    my $self = shift;

    my $sig = Protocol::OAuth::Signature->new(
        url                => 'http://api.twitter.com/1/statuses/update.json',
        oauth_consumer_key => 'GDdmIQH6jhtmLUypg82g',
        oauth_consumer_secret => 'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98',
        oauth_token => '819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw',
        oauth_token_secret => 'J6zix3FfA9LofH0awS24M3HcBYXO5nI1iYe8EfBA',
    );
    my $result = $sig->sign(
        {
            oauth_signature_method => 'HMAC-SHA1',
            oauth_nonce     => 'oElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y',
            oauth_timestamp => '1272325550',
            oauth_version   => '1.0',
            status => 'setting up my twitter 私のさえずりを設定する'
        }
    );

    is_deeply(
        $result,
        {
            base_string =>
'POST&http%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3DoElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1272325550%26oauth_token%3D819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw%26oauth_version%3D1.0%26status%3Dsetting%2520up%2520my%2520twitter%2520%25E7%25A7%2581%25E3%2581%25AE%25E3%2581%2595%25E3%2581%2588%25E3%2581%259A%25E3%2582%258A%25E3%2582%2592%25E8%25A8%25AD%25E5%25AE%259A%25E3%2581%2599%25E3%2582%258B',
            signing_key =>
'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98&J6zix3FfA9LofH0awS24M3HcBYXO5nI1iYe8EfBA',
            signature => 'yOahq5m0YjDDjfjxHaXEsW9D+X0=',
            params    => {
                oauth_consumer_key => 'GDdmIQH6jhtmLUypg82g',
                oauth_token =>
                  '819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw',
                oauth_signature_method => 'HMAC-SHA1',
                oauth_nonce     => 'oElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y',
                oauth_timestamp => '1272325550',
                oauth_version   => '1.0',
                oauth_signature => 'yOahq5m0YjDDjfjxHaXEsW9D+X0=',
            }
        }
    );
}

sub test_access_token2 : Test {
    my $self = shift;

    my $sig = Protocol::OAuth::Signature->new(
        method          => 'GET',
        url             => 'http://photos.example.net/photos',
        oauth_consumer_key    => 'dpf43f3p2l4k3l03',
        oauth_consumer_secret => 'kd94hf93k423kf44',
        oauth_token           => 'nnch734d00sl2jdk',
        oauth_token_secret    => 'pfkkdhi9sl3r4s00',
    );
    my $result = $sig->sign(
        {
            oauth_signature_method => 'HMAC-SHA1',
            oauth_nonce            => 'kllo9940pd9333jh',
            oauth_timestamp        => '1191242096',
            oauth_version          => '1.0',
            file                   => 'vacation.jpg',
            size                   => 'original'
        }
    );

    is_deeply(
        $result,
        {
            base_string =>
'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal',
            signing_key => 'kd94hf93k423kf44&pfkkdhi9sl3r4s00',
            signature   => 'tR3+Ty81lMeYAr/Fid0kMTYa/WM=',
            params      => {
                oauth_consumer_key     => 'dpf43f3p2l4k3l03',
                oauth_token            => 'nnch734d00sl2jdk',
                oauth_signature_method => 'HMAC-SHA1',
                oauth_nonce            => 'kllo9940pd9333jh',
                oauth_timestamp        => '1191242096',
                oauth_version          => '1.0',
                oauth_signature        => 'tR3+Ty81lMeYAr/Fid0kMTYa/WM=',
            }
        }
    );
}

sub _build_signature {
    my $self = shift;

    return Protocol::OAuth::Signature->new(@_);
}

1;
