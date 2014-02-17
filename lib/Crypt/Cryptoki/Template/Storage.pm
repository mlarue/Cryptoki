package Crypt::Cryptoki::Template::Storage;
use strict;
use Moo;
extends 'Crypt::Cryptoki::Template';
use Carp;

use Crypt::Cryptoki::Raw qw(
	CKA_TOKEN  TRUE
	CKA_LABEL
);

has 'token' => ( is => 'ro' );
has 'label' => ( is => 'ro' );

sub _attribute_map {+{
	%{shift->SUPER::_attribute_map},
	token => [ CKA_TOKEN, sub{pack('C',$_[0])}, sub{unpack('C',$_[0])} ],
	label => [ CKA_LABEL, sub{$_[0]}, sub{$_[0]} ],
}}

1;

