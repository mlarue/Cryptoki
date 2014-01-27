package Cryptoki;

use 5.018002;
use strict;
use warnings;
use Carp;

require Exporter;
use AutoLoader;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Cryptoki ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
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
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our $VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Cryptoki::constant not defined" if $constname eq 'constant';
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
XSLoader::load('Cryptoki', $VERSION);

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
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Cryptoki - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Cryptoki;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Cryptoki, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.

=head2 Exportable constants

  CK_NEED_ARG_LIST



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Markus Lauer, E<lt>markus-lauer@localdomainE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by Markus Lauer

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.18.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
