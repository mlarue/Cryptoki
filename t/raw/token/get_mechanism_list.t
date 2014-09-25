use Test::Most 'die';

use Crypt::Cryptoki::Raw;
use Crypt::Cryptoki::Constant qw(:all);
use YAML::Tiny;

my $cfg = YAML::Tiny->read('config.yml');
diag 'using: ', $cfg->[0]->{library};
ok my $raw = Crypt::Cryptoki::Raw->new($cfg->[0]->{library});
is($raw->C_Initialize(), CKR_OK, 'C_Initialize');

my $slot_id = 1;

my $mechanisms = [];
is(rv_to_str($raw->C_GetMechanismList($slot_id,$mechanisms)), 'CKR_OK', 'C_GetMechanismList');

my @mechanism_flags = qw(
	CKF_HW CKF_ENCRYPT CKF_DECRYPT CKF_DIGEST CKF_SIGN CKF_SIGN_RECOVER
	CKF_VERIFY CKF_VERIFY_RECOVER CKF_GENERATE CKF_GENERATE_KEY_PAIR
	CKF_WRAP CKF_UNWRAP CKF_DERIVE CKF_EXTENSION
);

sub flags_to_str {
	my $flags = shift;
	no strict 'refs';
	join('|', grep { $flags & $_->() } @mechanism_flags);
}

for ( @$mechanisms ) {
	my $minfo = {};
	is(rv_to_str($raw->C_GetMechanismInfo($slot_id,$_,$minfo)), 'CKR_OK', 'C_GetMechanismInfo');
	$minfo->{flags} = flags_to_str($minfo->{flags});
	explain ckm_to_str($_), ' ', $minfo;
}

is($raw->C_Finalize(), CKR_OK, 'C_Finalize');

done_testing;
