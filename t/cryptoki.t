use strict;
use warnings;

use Test::More;

use_ok 'Crypt::Cryptoki';
use_ok 'Crypt::Cryptoki::Template';

my $c = Crypt::Cryptoki->new(module=>'/usr/lib64/softhsm/libsofthsm.so');

my $info = $c->info;
my @slots = $c->slots( token => 1 );

for ( @slots ) {
	diag explain $_->info;
	diag explain $_->token_info;
}

my $session = $slots[0]->open_session(
	serial => 1,
	rw => 1
);

diag $session->login_user('1234');

# or
# diag $session->login_so('1234');

my $t_public = Crypt::Cryptoki::Template->new(
	class => 'public_key',
	key_type => 'rsa',
	token => 1,
	encrypt => 1,
	verify => 1,
	wrap => 1,
	modulus_bits => 4096,
	public_exponent => pack('C*', 0x01, 0x00, 0x01),
	label => 'test',
	id => pack('C*', 0x01, 0x02, 0x03)
);

my $t_private = Crypt::Cryptoki::Template->new(
	class => 'private_key',
	key_type => 'rsa',
	token => 1,
	decrypt => 1,
	sign => 1,
	unwrap => 1,
	label => 'test',
	id => pack('C*', 0x01, 0x02, 0x03)
);

my ( $public_key, $private_key ) = $session->generate_key_pair($t_public,$t_private);

my $plain_text = 'plain text';
my ( $encrypted_text_ref, $len ) = $public_key->encrypt(\$plain_text, length($plain_text));

my ( $encrypted_text_ref ) = $private_key->decrypt($encrypted_text_ref, $len);
diag $$encrypted_text_ref;

$public_key->destroy;
$private_key->destroy;

done_testing();
