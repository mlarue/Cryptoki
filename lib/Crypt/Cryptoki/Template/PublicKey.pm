package Crypt::Cryptoki::Template::PublicKey;
use strict;
use Moo;
extends 'Crypt::Cryptoki::Template::Key';
use Carp;

use Crypt::Cryptoki::Raw qw(
	CKA_ENCRYPT
	CKA_VERIFY
	CKA_WRAP
);

has '+class' => ( default => 'public_key' );

has 'encrypt' => ( is => 'ro', default => 0 );
has 'verify' => ( is => 'ro', default => 0 );
has 'wrap' => ( is => 'ro', default => 0 );

sub _attribute_map {+{
	%{shift->SUPER::_attribute_map},
	encrypt 		=> [ 
		CKA_ENCRYPT, sub{pack('C',shift)}, sub{unpack('C',@_)} 
	],
	modulus_bits	=> [ 
		CKA_VERIFY, sub{pack('C',@_)}, sub{unpack('C',@_)} 
	],
	public_exponent => [
		CKA_WRAP, sub{pack('C',@_)}, sub{unpack('C',@_)} 
	]
}}

1;
