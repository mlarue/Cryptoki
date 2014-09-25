use Test::Most;
die_on_fail;

use Crypt::Cryptoki::Raw;
use Crypt::Cryptoki::Constant qw(:all);
use YAML::Tiny;

my $cfg = YAML::Tiny->read('config.yml');
diag 'using: ', $cfg->[0]->{library};
ok my $raw = Crypt::Cryptoki::Raw->new($cfg->[0]->{library});

is($raw->C_Initialize(), CKR_OK, 'C_Initialize');

my $session;
is rv_to_str($raw->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,\$session)), 'CKR_OK', 'C_OpenSession';
diag 'session: ', $session;

# is(rv_to_str($raw->C_SeedRandom($session, "a\n\0c", 4)), 'CKR_OK', 'C_SeedRandom');

my $random;
is($raw->C_GenerateRandom($session, \$random, 10), CKR_OK, 'C_GenerateRandom');
diag 'random: ', unpack('H*', $random);
diag 'length: ', length($random);

is($raw->C_CloseSession($session), CKR_OK, 'C_CloseSession');

is($raw->C_Finalize(), CKR_OK, 'C_Finalize');

done_testing;
