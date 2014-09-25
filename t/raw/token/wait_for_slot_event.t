use Test::Most 'die';

use Crypt::Cryptoki::Raw;
use Crypt::Cryptoki::Constant qw(:all);
use YAML::Tiny;

my $cfg = YAML::Tiny->read('config.yml');
diag 'using: ', $cfg->[0]->{library};
ok my $raw = Crypt::Cryptoki::Raw->new($cfg->[0]->{library});
is($raw->C_Initialize(), CKR_OK, 'C_Initialize');

my $slot_id = -1;
while ( $slot_id < 0 ) {
	sleep 1;
	$raw->C_WaitForSlotEvent(CKF_DONT_BLOCK, \$slot_id);
	diag 'slot_id: ', $slot_id;
}

my %slot_info;
is $raw->C_GetSlotInfo($slot_id,\%slot_info), CKR_OK, 'C_GetSlotInfo';
explain \%slot_info;

if ( $slot_info{flags} & CKF_TOKEN_PRESENT ) {
	my %token_info;
	is $raw->C_GetTokenInfo($slot_id,\%token_info), CKR_OK, 'C_GetTokenInfo';
	explain \%token_info;
	
	if ( $token_info{flags} & CKF_TOKEN_INITIALIZED ) {
		diag 'token is initialized';
	}
	else {
		diag 'token is NOT initialized';
	}
}
else {
	diag 'token is NOT present';
}

is($raw->C_Finalize(), CKR_OK, 'C_Finalize');

done_testing;
