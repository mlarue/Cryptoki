package Crypt::Cryptoki::Template::PrivateKey;
use strict;
use Moo;
extends 'Crypt::Cryptoki::Template::Key';
use Carp;

use Crypt::Cryptoki::Raw qw(
	CKA_DECRYPT
	CKA_SIGN
	CKA_UNWRAP
);

has '+class' => ( default => 'private_key' );

has 'decrypt' => ( is => 'ro', default => 0 );
has 'sign' => ( is => 'ro', default => 0 );
has 'unwrap' => ( is => 'ro', default => 0 );

sub _attribute_map {+{
	%{shift->SUPER::_attribute_map},
	decrypt 		=> [ 
		CKA_DECRYPT, sub{pack('C',shift)}, sub{unpack('C',@_)} 
	],
	sign	=> [ 
		CKA_SIGN, sub{pack('C',@_)}, sub{unpack('C',@_)} 
	],
	unwrap => [
		CKA_UNWRAP, sub{pack('C',@_)}, sub{unpack('C',@_)} 
	]
}}

1;

