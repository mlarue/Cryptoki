use warnings;
use strict;

use Module::Build;
my $build_class = Module::Build->subclass(
	class => 'Crypt::Cryptoki::Build',
	code => q{
		sub ACTION_code {
			my $self = shift;
			require ExtUtils::ParseXS;
			ExtUtils::ParseXS::process_file(
				filename => 'src/Crypt-Cryptoki-FunctionList.xs',
				output   => 'src/Crypt-Cryptoki-FunctionList.c'
			);
			$self->SUPER::ACTION_code(@_);
		}
	}
);

my $build = Crypt::Cryptoki::Build->new(
	module_name => 'Crypt::Cryptoki',
	license => 'perl',
	build_requires => {
		'ExtUtils::CBuilder' => 0,
		'ExtUtils::Constant' => 0,
		'ExtUtils::ParseXS' => 0,
	},
	extra_compiler_flags => ['-Wall'],
	include_dirs => ['include'],
	autosplit => 'lib/Crypt/Cryptoki.pm',
	xs_files => {
		'src/Crypt-Cryptoki.xs' => 'lib/Crypt/Cryptoki.xs'
	},
	c_source => ['src'],
);

  my @names = (qw(
	CK_NEED_ARG_LIST 

	TRUE
	NULL_PTR

	CKR_OK 
	CKR_PIN_INCORRECT
	CKR_ARGUMENTS_BAD
	CKR_ATTRIBUTE_READ_ONLY
	CKR_ATTRIBUTE_TYPE_INVALID
	CKR_ATTRIBUTE_VALUE_INVALID
	CKR_CRYPTOKI_NOT_INITIALIZED
	CKR_DEVICE_ERROR
	CKR_DEVICE_MEMORY
	CKR_DEVICE_REMOVED
	CKR_DOMAIN_PARAMS_INVALID
	CKR_FUNCTION_CANCELED
	CKR_FUNCTION_FAILED
	CKR_GENERAL_ERROR
	CKR_HOST_MEMORY
	CKR_MECHANISM_INVALID
	CKR_MECHANISM_PARAM_INVALID
	CKR_OPERATION_ACTIVE
	CKR_OPERATION_NOT_INITIALIZED
	CKR_PIN_EXPIRED
	CKR_SESSION_CLOSED
	CKR_SESSION_HANDLE_INVALID
	CKR_SESSION_READ_ONLY
	CKR_SESSION_READ_ONLY_EXISTS
	CKR_TEMPLATE_INCOMPLETE
	CKR_TEMPLATE_INCONSISTENT
	CKR_TOKEN_WRITE_PROTECTED
	CKR_USER_NOT_LOGGED_IN

	CKF_SERIAL_SESSION 
	CKF_RW_SESSION

	CKU_USER 
	CKU_SO

    CKO_PRIVATE_KEY
	CKO_PUBLIC_KEY

	CKK_RSA

	CKS_RO_PUBLIC_SESSION
	CKS_RO_USER_FUNCTIONS
	CKS_RW_PUBLIC_SESSION
	CKS_RW_USER_FUNCTIONS
	CKS_RW_SO_FUNCTIONS

    CKA_CLASS
    CKA_KEY_TYPE 
    CKA_TOKEN
    CKA_PRIVATE
    CKA_SENSITIVE
    CKA_DECRYPT
    CKA_SIGN
    CKA_UNWRAP
    CKA_ENCRYPT
    CKA_VERIFY
    CKA_WRAP
    CKA_MODULUS_BITS
    CKA_PUBLIC_EXPONENT
	CKA_LABEL
	CKA_ID

	CKM_RSA_PKCS_KEY_PAIR_GEN
	CKM_RSA_PKCS
	CKM_SHA256_RSA_PKCS
	CKM_SHA512_RSA_PKCS
	CKM_SHA256
	CKM_SHA512
  ));

require ExtUtils::Constant;

  ExtUtils::Constant::WriteConstants(
  	NAME         => 'Crypt::Cryptoki',
    NAMES        => \@names,
    DEFAULT_TYPE => 'IV',
    C_FILE       => 'src/const-c.inc',
    XS_FILE      => 'src/const-xs.inc',
  );



$build->create_build_script;

