use warnings;
use strict;

use Test::More;

use_ok 'Crypt::Cryptoki::Template::RSAPublicKey';

my $t = Crypt::Cryptoki::Template::RSAPublicKey->new(
	label => 'hans'
);

diag explain $t;
my $_t = $t->build_template();
for (@$_t) {
	diag $_->[0], ': ', unpack('H*', $_->[1]);
}

done_testing();
