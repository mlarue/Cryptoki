package Crypt::Cryptoki::Constant;

use strict;
use warnings;
use Carp;

require Exporter;
use AutoLoader;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = ( 'all' => [ qw(
	rv_to_str

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
	CKR_ENCRYPTED_DATA_INVALID

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
    CKA_MODULUS
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
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Crypt::Cryptoki::Constant::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('Crypt::Cryptoki::Constant');

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

my %rv_map;
{
	no strict 'refs';
	%rv_map = map { $_->() => $_ } grep { /^CKR/ } @EXPORT_OK;
}

sub rv_to_str {
	my ( $err_num ) = @_;
	return $rv_map{$err_num} || 'n/a ('.$err_num.')';
}

1;
__END__
=head1 NAME

Crypt::Cryptoki::Raw - "Low-level" Perl extension for PKCS#11

=head1 SYNOPSIS

	use Crypt::Cryptoki::Raw qw(:all);

	my $f = Crypt::Cryptoki::Raw::load('/usr/lib64/softhsm/libsofthsm.so');

	$f->C_Initialize;

	my $info = {};
	$f->C_GetInfo($info);

	my $slots = [];
	$f->C_GetSlotList(1,$slots);

	for my $id ( @$slots ) {
		my $slotInfo = {};
		$f->C_GetSlotInfo($id,$slotInfo);

		my $tokenInfo = {};
		$f->C_GetTokenInfo($id,$tokenInfo);
	}

	my $session = -1;
	$f->C_OpenSession(0,CKF_SERIAL_SESSION|CKF_RW_SESSION,$session);

	$f->C_Login($session, CKU_USER, '1234'));

	
	(see also: t/softhsm.t)


=head1 DESCRIPTION

This module brings the "Cryptoki" to perl. It is nearly a one-to-one mapping
from C to Perl and vice versa.

"RSA Security Inc. Public-Key Cryptography Standards (PKCS)"

Original documentation: L<ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20.pdf>

C header files and documentation are also part of the distribution.

=head2 FUNCTIONS

	C_Initialize
	C_GetInfo
	C_GetSlotList
	C_GetSlotInfo
	C_GetTokenInfo
	C_OpenSession
	C_GetSessionInfo
	C_Login
	C_GenerateKeyPair
	C_EncryptInit
	C_Encrypt
	C_DecryptInit
	C_Decrypt
	C_SignInit
	C_Sign
	C_VerifyInit
	C_Verify
	C_DestroyObject

=head2 EXPORT

None by default.

=head2 Exportable constants

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

=head2 TODO

Everything to cover Cryptoki 2.20. Especially the incremental functions.

=head1 SEE ALSO

L<http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-11-cryptographic-token-interface-standard.htm>

L<https://www.oasis-open.org/committees/pkcs11>

=head1 AUTHOR

Markus Lauer, E<lt>mlarue@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by Markus Lauer

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.5 or,
at your option, any later version of Perl 5 you may have available.


=cut
