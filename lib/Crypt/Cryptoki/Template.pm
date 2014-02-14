package Crypt::Cryptoki::Template;
use strict;
use Moo;
use Carp;

use Crypt::Cryptoki::Raw qw(
	CKA_CLASS  CKO_PUBLIC_KEY  CKO_PRIVATE_KEY
	CKA_KEY_TYPE  CKK_RSA
	CKA_TOKEN  TRUE
	CKA_ENCRYPT
	CKA_DECRYPT
	CKA_VERIFY
	CKA_SIGN
	CKA_WRAP
	CKA_UNWRAP
	CKA_MODULUS_BITS
	CKA_PUBLIC_EXPONENT
	CKA_LABEL
	CKA_ID
);

has 'class' => ( is => 'ro' );
has 'key_type' => ( is => 'ro' );
has 'token' => ( is => 'ro' );
has 'encrypt' => ( is => 'ro' );
has 'decrypt' => ( is => 'ro' );
has 'verify' => ( is => 'ro' );
has 'sign' => ( is => 'ro' );
has 'wrap' => ( is => 'ro' );
has 'unwrap' => ( is => 'ro' );
has 'modulus_bits' => ( is => 'ro' );
has 'public_exponent' => ( is => 'ro' );
has 'label' => ( is => 'ro' );
has 'id' => ( is => 'ro' );

has 'template' => ( is => 'lazy' );

sub _build_template {
	my $self = shift;

	my @attrs;

	if ( $self->class ) {
		my %m = (
			public_key => CKO_PUBLIC_KEY,
			private_key => CKO_PRIVATE_KEY
		);
		defined $m{$self->class} or croak 'illegal class'; 
		push @attrs, [ CKA_CLASS, pack('Q',$m{$self->class}) ];
	}

	if ( $self->key_type ) {
		my %m = (
			rsa => CKK_RSA,
		);
		defined $m{$self->key_type} or croak 'illegal key_type'; 
		push @attrs, [ CKA_KEY_TYPE, pack('Q',$m{$self->key_type}) ];
	}

	if ( $self->token ) {
		# bool
		push @attrs, [ CKA_TOKEN, pack('C',$self->token) ];
	}

	if ( $self->encrypt ) {
		# bool
		push @attrs, [ CKA_ENCRYPT, pack('C',$self->encrypt) ];
	}

	if ( $self->decrypt ) {
		# bool
		push @attrs, [ CKA_DECRYPT, pack('C',$self->decrypt) ];
	}

	if ( $self->sign ) {
		# bool
		push @attrs, [ CKA_SIGN, pack('C',$self->sign) ];
	}

	if ( $self->verify ) {
		# bool
		push @attrs, [ CKA_VERIFY, pack('C',$self->verify) ];
	}

	if ( $self->wrap ) {
		# bool
		push @attrs, [ CKA_WRAP, pack('C',$self->wrap) ];
	}

	if ( $self->unwrap ) {
		# bool
		push @attrs, [ CKA_UNWRAP, pack('C',$self->unwrap) ];
	}

	if ( $self->modulus_bits ) {
		push @attrs, [ CKA_MODULUS_BITS, pack('Q',$self->modulus_bits) ];
	}

	if ( $self->public_exponent ) {
		push @attrs, [ CKA_PUBLIC_EXPONENT, $self->public_exponent ];
	}

	if ( $self->label ) {
		push @attrs, [ CKA_LABEL, $self->label ];
	}

	if ( $self->id ) {
		push @attrs, [ CKA_ID, $self->id ];
	}

	return \@attrs;
}

1;
