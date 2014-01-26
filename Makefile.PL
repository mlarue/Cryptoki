use 5.018002;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Cryptoki',
    VERSION_FROM      => 'lib/Cryptoki.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Cryptoki.pm', # retrieve abstract from module
       AUTHOR         => 'Markus Lauer <ml@usermode.de>') : ()),
    LIBS              => [''], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    OBJECT            => '$(O_FILES)', # link all the C files too
);
if  (eval {require ExtUtils::Constant; 1}) {
  # If you edit these definitions to change the constants used by this module,
  # you will need to use the generated const-c.inc and const-xs.inc
  # files to replace their "fallback" counterparts before distributing your
  # changes.
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
  ));
  ExtUtils::Constant::WriteConstants(
                                     NAME         => 'Cryptoki',
                                     NAMES        => \@names,
                                     DEFAULT_TYPE => 'IV',
                                     C_FILE       => 'const-c.inc',
                                     XS_FILE      => 'const-xs.inc',
                                  );

}
else {
  use File::Copy;
  use File::Spec;
  foreach my $file ('const-c.inc', 'const-xs.inc') {
    my $fallback = File::Spec->catfile('fallback', $file);
    copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
  }
}
