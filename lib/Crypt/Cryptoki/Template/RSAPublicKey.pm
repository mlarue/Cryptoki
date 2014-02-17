package Crypt::Cryptoki::Template::RSAPublicKey;
use strict;
use Moo;
extends 'Crypt::Cryptoki::Template::PublicKey';
use Carp;

use Crypt::Cryptoki::Raw qw(
	CKA_MODULUS
	CKA_MODULUS_BITS
	CKA_PUBLIC_EXPONENT
);

has '+key_type' => ( default => 'rsa' );

has 'modulus' => ( is => 'ro' );
has 'modulus_bits' => ( is => 'ro' );
has 'public_exponent' => ( is => 'ro' );

sub _attribute_map {+{
	%{shift->SUPER::_attribute_map},

	modulus => [ 
		CKA_MODULUS, sub{$_[0]}, sub{$_[0]}, 1
	],
	modulus_bits => [ 
		CKA_MODULUS_BITS, 
		sub{pack('Q',shift)}, 
		sub{unpack('Q',$_[0])} 
	],
	public_exponent => [
		CKA_PUBLIC_EXPONENT, sub{$_[0]}, sub{$_[0]}, 1
	]
}}

1;

