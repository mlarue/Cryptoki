use Test::Most 'die';

use Crypt::Cryptoki::Raw;
use Crypt::Cryptoki::Constant qw(:all);
use YAML::Tiny;

my $cfg = YAML::Tiny->read('config.yml');
diag 'using: ', $cfg->[0]->{library};
ok my $raw = Crypt::Cryptoki::Raw->new($cfg->[0]->{library});
is($raw->C_Initialize(), CKR_OK, 'C_Initialize');

my $slot_id = 1;

my $session;
is rv_to_str($raw->C_OpenSession($slot_id,CKF_SERIAL_SESSION|CKF_RW_SESSION,\$session)), 'CKR_OK', 'C_OpenSession';

diag "Enter User-PIN: ";
my $user_pin = <STDIN>;
chomp($user_pin);
is rv_to_str($raw->C_Login($session, CKU_USER, $user_pin)), 'CKR_OK', 'C_Login';

# logged in user; User-PIN
is(rv_to_str($raw->C_SetPIN($session, $user_pin, '123456')), 'CKR_OK', 'C_SetPIN');

is($raw->C_Logout($session), CKR_OK, 'C_Logout');
is($raw->C_CloseSession($session), CKR_OK, 'C_CloseSession');
is($raw->C_Finalize(), CKR_OK, 'C_Finalize');

done_testing;
