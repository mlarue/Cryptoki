use Test::Most 'die';

use Crypt::Cryptoki::Raw;
use Crypt::Cryptoki::Constant qw(:all);
use YAML::Tiny;

my $cfg = YAML::Tiny->read('config.yml');
diag 'using: ', $cfg->[0]->{library};
ok my $raw = Crypt::Cryptoki::Raw->new($cfg->[0]->{library});
is($raw->C_Initialize(), CKR_OK, 'C_Initialize');

my $slot_id = 1;

# SO-PIN
#is(rv_to_str($raw->C_InitToken($slot_id,'1234','testtoken')), 'CKR_OK', 'C_InitToken');

my $session;
is rv_to_str($raw->C_OpenSession($slot_id,CKF_SERIAL_SESSION|CKF_RW_SESSION,\$session)), 'CKR_OK', 'C_OpenSession';

diag "WARNING: The SO-PIN has a retry counter of 15 and can not be unblocked.";
diag "Enter SO-PIN: ";
my $pin_so = <STDIN>;
chomp($pin_so);
is rv_to_str($raw->C_Login($session, CKU_SO, $pin_so)), 'CKR_OK', 'C_Login';

# User-PIN
is(rv_to_str($raw->C_InitPIN($session,'123456')), 'CKR_OK', 'C_InitPIN');

# logged in user; SO-PIN
#is(rv_to_str($raw->C_SetPIN($session,'old_pin','new_pin')), 'CKR_OK', 'C_SetPIN');

is($raw->C_Logout($session), CKR_OK, 'C_Logout');
is($raw->C_CloseSession($session), CKR_OK, 'C_CloseSession');
is($raw->C_Finalize(), CKR_OK, 'C_Finalize');

done_testing;
