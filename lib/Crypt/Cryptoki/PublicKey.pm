package Crypt::Cryptoki::PublicKey;
use strict;
use Moo;
extends 'Crypt::Cryptoki::Key';
use Carp;

use Crypt::Cryptoki::Raw qw(rv_to_str CKR_OK NULL_PTR
	CKM_RSA_PKCS 
	CKA_MODULUS CKA_PUBLIC_EXPONENT
);

sub _attribute_map {{
	modulus 		=> CKA_MODULUS,
	public_exponent => CKA_PUBLIC_EXPONENT
}};

sub export_as_string {
	my ( $self ) = @_;
	my $attrs = $self->attributes;
	require Crypt::OpenSSL::Bignum;
	require Crypt::OpenSSL::RSA;
	my $n = Crypt::OpenSSL::Bignum->new_from_bin($attrs->{modulus});
	my $e = Crypt::OpenSSL::Bignum->new_from_bin($attrs->{public_exponent});
	my $rsa_pub = Crypt::OpenSSL::RSA->new_key_from_parameters($n,$e);
	$rsa_pub->use_pkcs1_padding;
	$rsa_pub->get_public_key_string;
}

sub encrypt {
	my ( $self, $plain_text_ref, $plain_text_len ) = @_;

	my $rv = $self->_fl->C_EncryptInit(
		$self->session->id, 
		[ CKM_RSA_PKCS, NULL_PTR, 0 ], 
		$self->id
	);
	if ( $rv != CKR_OK ) {
		croak rv_to_str($rv);
	}

	my $encrypted_text = '';
	my $encrypted_text_len = -1;

	$rv = $self->_fl->C_Encrypt(
		$self->session->id, 
		$$plain_text_ref,
		$plain_text_len,
		$encrypted_text,
		$encrypted_text_len
	);
	if ( $rv != CKR_OK ) {
		croak rv_to_str($rv);
	}

	return ( \$encrypted_text, $encrypted_text_len );
}

1;
