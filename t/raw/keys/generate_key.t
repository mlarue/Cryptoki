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
is rv_to_str($raw->C_Login($session, CKU_USER, '123456')), 'CKR_OK', 'C_Login';

my $key_template = [
    [ CKA_TOKEN,      pack('C',1) ],
    [ CKA_PRIVATE,    pack('C',1) ],
    [ CKA_SENSITIVE,  pack('C',1) ],
    [ CKA_DECRYPT,    pack('C',1) ],
    [ CKA_SIGN,       pack('C',1) ],
    [ CKA_UNWRAP,     pack('C',1) ],
    [ CKA_LABEL,      'test' ],
	[ CKA_ID, 		  pack('C*', 0x04, 0x05, 0x06) ],
];

my $key;
is rv_to_str($raw->C_GenerateKey(
	$session, 
	[ CKM_DES_KEY_GEN, undef, 0 ], 
	$key_template,
	\$key, 
)), 'CKR_OK', 'C_GenerateKey';

diag $key;
#diag $private_key;

is($raw->C_Logout($session), CKR_OK, 'C_Logout');
is($raw->C_CloseSession($session), CKR_OK, 'C_CloseSession');
is($raw->C_Finalize(), CKR_OK, 'C_Finalize');

done_testing();
