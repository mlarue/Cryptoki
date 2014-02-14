package Crypt::Cryptoki::Template;
use strict;
use Moo;
use Carp;

use Crypt::Cryptoki::Raw qw(CKA_CLASS CKO_PUBLIC_KEY CKO_PRIVATE_KEY);

has 'class' => ( is => 'ro' );
has 'key_type' => ( is => 'ro' );
has 'token' => ( is => 'ro' );
has 'encrypt' => ( is => 'ro' );
has 'verify' => ( is => 'ro' );
has 'wrap' => ( is => 'ro' );
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

	return \@attrs;
}

1;
