use strict;
use warnings;

use Test::More;
BEGIN { use_ok('Cryptoki', qw/:all/) };

my $f = Cryptoki::load('/usr/lib64/softhsm/libsofthsm.so');
ok $f, 'load';

is $f->C_Initialize, CKR_OK, 'C_Initialize';

my $info = {};
is $f->C_GetInfo($info), CKR_OK, 'C_GetInfo';
diag explain $info;

my $slots = [];
is $f->C_GetSlotList(1,$slots), CKR_OK, 'C_GetSlotList';

for my $id ( @$slots ) {
	diag 'slotID: ', $id;
	my $slotInfo = {};
	is $f->C_GetSlotInfo($id,$slotInfo), CKR_OK, 'C_GetSlotInfo';
	diag explain $slotInfo;

	my $tokenInfo = {};
	is $f->C_GetTokenInfo($id,$tokenInfo), CKR_OK, 'C_GetTokenInfo';
	diag explain $tokenInfo;
}

my $session = -1;
is rv_to_str($f->C_OpenSession(0,CKF_SERIAL_SESSION|CKF_RW_SESSION,$session)), 'CKR_OK', 'C_OpenSession';
diag $session;

my $sessionInfo = {};
is $f->C_GetSessionInfo($session, $sessionInfo), CKR_OK, 'C_GetSessionInfo';
diag explain $sessionInfo;
diag 'CKS_RO_PUBLIC_SESSION' if $sessionInfo->{state} & CKS_RO_PUBLIC_SESSION;
diag 'CKS_RO_USER_FUNCTIONS' if $sessionInfo->{state} & CKS_RO_USER_FUNCTIONS;
diag 'CKS_RW_PUBLIC_SESSION' if $sessionInfo->{state} & CKS_RW_PUBLIC_SESSION;
diag 'CKS_RW_USER_FUNCTIONS' if $sessionInfo->{state} & CKS_RW_USER_FUNCTIONS;
diag 'CKS_RW_SO_FUNCTIONS'   if $sessionInfo->{state} & CKS_RW_SO_FUNCTIONS;

is rv_to_str($f->C_Login($session, CKU_USER, '1234')), 'CKR_OK', 'C_Login';

#diag unpack('H*',pack('L',CKO_PUBLIC_KEY));
#diag unpack('H*',pack('C*',0x01, 0x00, 0x01));

my $public_key_template = [
    [ CKA_CLASS ,          pack('Q',CKO_PUBLIC_KEY) ],
    [ CKA_KEY_TYPE,        pack('Q',CKK_RSA) ],
    [ CKA_TOKEN,           pack('C',TRUE) ],
    [ CKA_ENCRYPT,         pack('C',TRUE) ],
    [ CKA_VERIFY,          pack('C',TRUE) ],
    [ CKA_WRAP,            pack('C',TRUE) ],
    [ CKA_MODULUS_BITS,    pack('Q',4096) ],
    [ CKA_PUBLIC_EXPONENT, pack('C*', 0x01, 0x00, 0x01) ],
    [ CKA_LABEL,    	   'test_pub' ],
	[ CKA_ID, 			   pack('C*', 0x01, 0x02, 0x03) ],
];

my $private_key_template = [
    [ CKA_CLASS,      pack('Q',CKO_PRIVATE_KEY) ],
    [ CKA_KEY_TYPE,   pack('Q',CKK_RSA) ],
    [ CKA_TOKEN,      pack('C',TRUE) ],
    [ CKA_PRIVATE,    pack('C',TRUE) ],
    [ CKA_SENSITIVE,  pack('C',TRUE) ],
    [ CKA_DECRYPT,    pack('C',TRUE) ],
    [ CKA_SIGN,       pack('C',TRUE) ],
    [ CKA_UNWRAP,     pack('C',TRUE) ],
    [ CKA_LABEL,      'test' ],
	[ CKA_ID, 		  pack('C*', 0x04, 0x05, 0x06) ],
];

my $private_key = -1;
my $public_key = -1;

is rv_to_str($f->C_GenerateKeyPair(
	$session, 
	[ CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 ], 
	$public_key_template,
    $private_key_template,
	$public_key, 
	$private_key
)), 'CKR_OK', 'C_GenerateKeyPair';



is rv_to_str($f->C_EncryptInit(
	$session, 
	[ CKM_RSA_PKCS, NULL_PTR, 0 ], 
	$public_key, 
)), 'CKR_OK', 'C_EncryptInit';

my $plain_text = 'plain text';
my $encrypted_text = '';
my $encrypted_text_len = 0;
is rv_to_str($f->C_Encrypt(
	$session, 
	$plain_text,
	length($plain_text),
	$encrypted_text,
	$encrypted_text_len
)), 'CKR_OK', 'C_Encrypt';
diag unpack('H*',$encrypted_text);

is rv_to_str($f->C_DecryptInit(
	$session, 
	[ CKM_RSA_PKCS, NULL_PTR, 0 ], 
	$private_key, 
)), 'CKR_OK', 'C_DecryptInit';


my $decrypted_text = '';
my $decrypted_text_len = 0;
is rv_to_str($f->C_Decrypt(
	$session, 
	$encrypted_text,
	$encrypted_text_len,
	$decrypted_text,
	$decrypted_text_len,
)), 'CKR_OK', 'C_Decrypt';
diag $decrypted_text;

is $decrypted_text, $plain_text, 'decrypt: "plain text"';


is rv_to_str($f->C_SignInit(
	$session, 
	[ CKM_SHA256_RSA_PKCS, NULL_PTR, 0 ], 
	$private_key, 
)), 'CKR_OK', 'C_SignInit';

my $signature = '';
my $signature_len = 0;
is rv_to_str($f->C_Sign(
	$session, 
	$plain_text,
	length($plain_text),
	$signature,
	$signature_len,
)), 'CKR_OK', 'C_Sign';
diag unpack('H*',$signature);
diag $signature_len;


is rv_to_str($f->C_VerifyInit(
	$session, 
	[ CKM_SHA256_RSA_PKCS, NULL_PTR, 0 ], 
	$public_key, 
)), 'CKR_OK', 'C_VerifyInit';

is rv_to_str($f->C_Verify(
	$session, 
	$plain_text,
	length($plain_text),
	$signature,
	$signature_len,
)), 'CKR_OK', 'C_Verify';



is $f->C_DestroyObject($session, $public_key), CKR_OK, 'destroy public key';
is $f->C_DestroyObject($session, $private_key), CKR_OK, 'destroy private key';


done_testing();

