use Test::Most;

use Crypt::Cryptoki::Raw;
use Crypt::Cryptoki::Constant qw(:all);
use Digest::SHA qw(sha512);

my $f = Crypt::Cryptoki::Raw->new('/usr/lib64/softhsm/libsofthsm.so');

ok $f, 'load';

is $f->C_Initialize, CKR_OK, 'C_Initialize';

my $session = -1;
is rv_to_str($f->C_OpenSession(0,CKF_SERIAL_SESSION|CKF_RW_SESSION,$session)), 'CKR_OK', 'C_OpenSession';

is rv_to_str($f->C_Login($session, CKU_USER, '1234')), 'CKR_OK', 'C_Login';

is rv_to_str($f->C_DigestInit(
	$session, 
	[ CKM_SHA512, undef, 0 ], 
)), 'CKR_OK', 'C_DigestInit';

my $data = 'Bedenkt, Ihr habet weiches Holz zu spalten.';
my $digest = '';
my $digest_len = -1;
is rv_to_str($f->C_Digest(
	$session, 
	$data,
	length($data),
	$digest,
	$digest_len
)), 'CKR_OK', 'C_Digest';

is($digest, sha512($data), 'digest');

diag 'digest: ', unpack('H*', $digest);

done_testing();
