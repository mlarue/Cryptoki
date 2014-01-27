use strict;
use warnings;

use Test::More;
BEGIN { use_ok('Lib::PKCS11') };

my $funcs = Lib::PKCS11::pkcs11_get_function_list('/usr/lib64/softhsm/libsofthsm.so');
diag explain $funcs;

is Lib::PKCS11::C_Initialize($funcs), Lib::PKCS11::CKR_OK(), 'C_Initialize';

my $info;
is Lib::PKCS11::C_GetInfo($funcs,$info), Lib::PKCS11::CKR_OK(), 'C_GetInfo';
diag explain $info;

diag $info->manufacturerID;

my %info2;
my $info3 = {};
is Lib::PKCS11::C_GetInfo2($funcs,$info3), Lib::PKCS11::CKR_OK(), 'C_GetInfo2';
diag explain $info3;

done_testing();
