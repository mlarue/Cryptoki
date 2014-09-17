use Test::Most;
die_on_fail;

use Crypt::Cryptoki::Raw;
use Crypt::Cryptoki::Constant qw(:all);

ok my $raw = Crypt::Cryptoki::Raw->new('/usr/lib64/softhsm/libsofthsm.so');

is($raw->C_Initialize(), CKR_OK, 'C_Initialize');

#my $slot_id;
#is(rv_to_str($raw->C_WaitForSlotEvent(CKF_DONT_BLOCK, $slot_id)), 'CKR_OK', 'C_WaitForSlotEvent');
#diag 'slot_id: ', $slot_id;

my $slot_id = 0;
my $mechanisms = [];
is(rv_to_str($raw->C_GetMechanismList($slot_id,$mechanisms)), 'CKR_OK', 'C_GetMechanismList');
#explain [ map { ckm_to_str($_) } @$mechanisms ];

#
# TODO: proper flags handling; CKF_* has duplicate values, so ckf_to_str does
#       not work automatically
#

my @mechanism_flags = qw(
	CKF_HW CKF_ENCRYPT CKF_DECRYPT CKF_DIGEST CKF_SIGN CKF_SIGN_RECOVER
	CKF_VERIFY CKF_VERIFY_RECOVER CKF_GENERATE CKF_GENERATE_KEY_PAIR
	CKF_WRAP CKF_UNWRAP CKF_DERIVE CKF_EXTENSION
);

sub flags_to_str {
	my $flags = shift;
	my @res = ();
	for (@mechanism_flags) {
		no strict 'refs';
		push @res, $_ if $flags & $_->();
	}	
	join('|', @res);
}

for ( @$mechanisms ) {
	my $minfo = {};
	is(rv_to_str($raw->C_GetMechanismInfo($slot_id,$_,$minfo)), 'CKR_OK', 'C_GetMechanismInfo');
	$minfo->{flags} = flags_to_str($minfo->{flags});
	explain ckm_to_str($_), ' ', $minfo;
}

#$slot_id = 1;
#is(rv_to_str($raw->C_InitToken($slot_id,'test_pin',length('test_pin'),'test_token')), 'CKR_OK', 'C_InitToken');

#is(rv_to_str($raw->C_InitPIN($session,'test_pin',length('test_pin'))), 'CKR_OK', 'C_InitPIN');

#is(rv_to_str($raw->C_SetPIN(
#	$session,
#	'old_pin',length('old_pin'),
#	'new_pin',length('new_pin')
#)), 'CKR_OK', 'C_SetPIN');


is($raw->C_Finalize(), CKR_OK, 'C_Finalize');

done_testing;
