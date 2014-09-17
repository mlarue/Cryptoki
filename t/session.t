use Test::Most;
die_on_fail;

use Crypt::Cryptoki::Raw;
use Crypt::Cryptoki::Constant qw(:all);

ok my $raw = Crypt::Cryptoki::Raw->new('/usr/lib64/softhsm/libsofthsm.so');

is($raw->C_Initialize(), CKR_OK, 'C_Initialize');

my $slotID = 0;
my $session;
is rv_to_str($raw->C_OpenSession($slotID,CKF_SERIAL_SESSION|CKF_RW_SESSION,$session)), 'CKR_OK', 'C_OpenSession';

is rv_to_str($raw->C_Login($session, CKU_USER, '1234')), 'CKR_OK', 'C_Login';

is($raw->C_Logout($session), CKR_OK, 'C_Logout');

is($raw->C_CloseSession($session), CKR_OK, 'C_CloseSession');


is rv_to_str($raw->C_OpenSession($slotID,CKF_SERIAL_SESSION|CKF_RW_SESSION,$session)), 'CKR_OK', 'C_OpenSession';
my $session2;
is rv_to_str($raw->C_OpenSession($slotID,CKF_SERIAL_SESSION,$session2)), 'CKR_OK', 'C_OpenSession 2';

is($raw->C_CloseAllSessions($slotID), CKR_OK, 'C_CloseAllSessions');

is($raw->C_Finalize(), CKR_OK, 'C_Finalize');

done_testing;
