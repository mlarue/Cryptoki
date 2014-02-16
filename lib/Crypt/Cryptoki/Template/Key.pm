package Crypt::Cryptoki::Template::Key;
use strict;
use Moo;
extends 'Crypt::Cryptoki::Template::Storage';
use Carp;

use Crypt::Cryptoki::Raw qw(
	CKA_KEY_TYPE  CKK_RSA
	CKA_ID
);

has 'key_type' => ( is => 'ro', default => 'rsa' );
has 'id' => ( is => 'ro', default => '' );

my $kt_map = {
	rsa => CKK_RSA,
};
my $reverse_kt_map = { reverse %$kt_map };

sub _attribute_map {+{
	%{shift->SUPER::_attribute_map},
	key_type => [ 
		CKA_KEY_TYPE, sub{pack('Q',$kt_map->{shift()})}, sub{$reverse_kt_map->{unpack('Q',@_)}} 
	],
	id => [
		CKA_ID, sub{shift}, sub{@_} 
	]
}}

1;

