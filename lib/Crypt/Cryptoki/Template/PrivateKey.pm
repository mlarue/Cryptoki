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

has 'decrypt' => ( is => 'ro' );
has 'sign' => ( is => 'ro' );
has 'unwrap' => ( is => 'ro' );

sub _attribute_map {+{
	%{shift->SUPER::_attribute_map},
	decrypt => [ 
		CKA_DECRYPT, sub{pack('C',$_[0])}, sub{unpack('C',$_[0])} 
	],
	sign => [ 
		CKA_SIGN, sub{pack('C',$_[0])}, sub{unpack('C',$_[0])} 
	],
	unwrap => [
		CKA_UNWRAP, sub{pack('C',$_[0])}, sub{unpack('C',$_[0])} 
	]
}}

1;

