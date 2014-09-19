use Test::Most;

use Crypt::Cryptoki::Raw;
use Crypt::Cryptoki::Constant qw(:all);

my $f = Crypt::Cryptoki::Raw->new('/usr/lib64/softhsm/libsofthsm.so');

ok $f, 'load';

is $f->C_Initialize, CKR_OK, 'C_Initialize';

my $info = {};
is $f->C_GetInfo($info), CKR_OK, 'C_GetInfo';
diag explain $info;

my $session = -1;
is rv_to_str($f->C_OpenSession(0,CKF_SERIAL_SESSION|CKF_RW_SESSION,$session)), 'CKR_OK', 'C_OpenSession';
diag $session;

is rv_to_str($f->C_Login($session, CKU_USER, '1234')), 'CKR_OK', 'C_Login';

my $public_key_template = [
    [ CKA_CLASS ,          pack('Q',CKO_PUBLIC_KEY) ],
    [ CKA_KEY_TYPE,        pack('Q',CKK_RSA) ],
    [ CKA_TOKEN,           pack('C',1) ],
    [ CKA_ENCRYPT,         pack('C',1) ],
    [ CKA_VERIFY,          pack('C',1) ],
    [ CKA_WRAP,            pack('C',1) ],
    [ CKA_MODULUS_BITS,    pack('Q',4096) ],
    [ CKA_PUBLIC_EXPONENT, pack('C*', 0x01, 0x00, 0x01) ],
    [ CKA_LABEL,    	   'test_pub' ],
	[ CKA_ID, 			   pack('C*', 0x01, 0x02, 0x03) ],
];

my $private_key_template = [
    [ CKA_CLASS,      pack('Q',CKO_PRIVATE_KEY) ],
    [ CKA_KEY_TYPE,   pack('Q',CKK_RSA) ],
    [ CKA_TOKEN,      pack('C',1) ],
    [ CKA_PRIVATE,    pack('C',1) ],
    [ CKA_SENSITIVE,  pack('C',1) ],
    [ CKA_DECRYPT,    pack('C',1) ],
    [ CKA_SIGN,       pack('C',1) ],
    [ CKA_UNWRAP,     pack('C',1) ],
    [ CKA_LABEL,      'test' ],
	[ CKA_ID, 		  pack('C*', 0x04, 0x05, 0x06) ],
];

my $private_key = -1;
my $private_key_2 = -1;
my $public_key = -1;

is rv_to_str($f->C_GenerateKey(
	$session, 
	[ CKM_RSA_PKCS_KEY_PAIR_GEN, undef, 0 ], 
	$public_key_template,
	$public_key, 
)), 'CKR_OK', 'C_GenerateKey';

diag $public_key;
#diag $private_key;

my $wrapped_key;
my $wrapped_key_length;
is rv_to_str($f->C_WrapKey(
	$session, 
	[ CKM_RSA_PKCS_KEY_PAIR_GEN, undef, 0 ], 
	$private_key,
	$private_key_2,
	$wrapped_key,
	$wrapped_key_length 
)), 'CKR_OK', 'C_WrapKey';



is $f->C_DestroyObject($session, $public_key), CKR_OK, 'destroy public key';
#is $f->C_DestroyObject($session, $private_key), CKR_OK, 'destroy private key';

done_testing();

