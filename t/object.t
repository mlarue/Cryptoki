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

my $data_template = [
	[ CKA_CLASS,       pack('Q',CKO_DATA) ],
	[ CKA_TOKEN,       pack('C',0) ],
	[ CKA_APPLICATION, 'testapplication' ],
	[ CKA_VALUE,       'testdata' ]
];

my $public_key_template = [
    [ CKA_CLASS ,          pack('Q',CKO_PUBLIC_KEY) ],
    [ CKA_KEY_TYPE,        pack('Q',CKK_RSA) ],
    [ CKA_TOKEN,           pack('C',0) ],
    [ CKA_ENCRYPT,         pack('C',1) ],
    [ CKA_VERIFY,          pack('C',1) ],
    [ CKA_WRAP,            pack('C',0) ],
    [ CKA_MODULUS_BITS,    pack('Q',4096) ],
    [ CKA_PUBLIC_EXPONENT, pack('C*', 0x01, 0x00, 0x01) ],
    [ CKA_LABEL,    	   'test_pub_666' ],
	[ CKA_ID, 			   pack('C*', 0x06, 0x06, 0x06) ],
];

my $object = -1;
is(rv_to_str($raw->C_CreateObject($session,$public_key_template,$object)), 'CKR_OK', 'C_CreateObject');
diag "object: ", $object;


is($raw->C_Logout($session), CKR_OK, 'C_Logout');
is($raw->C_CloseSession($session), CKR_OK, 'C_CloseSession');
is($raw->C_Finalize(), CKR_OK, 'C_Finalize');

done_testing;
