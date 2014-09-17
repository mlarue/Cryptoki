use Test::Most;
die_on_fail;

use Crypt::Cryptoki::Raw;
use Crypt::Cryptoki::Constant qw(:all);

ok my $raw = Crypt::Cryptoki::Raw->new('/usr/lib64/softhsm/libsofthsm.so');
explain $raw;

is($raw->C_Initialize(), CKR_OK, 'C_Initialize');

my $session = -1;
is rv_to_str($raw->C_OpenSession(0,CKF_SERIAL_SESSION|CKF_RW_SESSION,$session)), 'CKR_OK', 'C_OpenSession';
diag $session;

is($raw->C_SeedRandom($session, 'abc', 3), CKR_OK, 'C_SeedRandom');

my $random;
is($raw->C_GenerateRandom($session, $random, 10), CKR_OK, 'C_GenerateRandom');
diag 'random: ', unpack('H*', $random);

done_testing;
