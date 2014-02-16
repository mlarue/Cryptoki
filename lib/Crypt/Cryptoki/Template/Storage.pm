package Crypt::Cryptoki::Template::Storage;
use strict;
use Moo;
extends 'Crypt::Cryptoki::Template';
use Carp;

use Crypt::Cryptoki::Raw qw(
	CKA_TOKEN  TRUE
	CKA_LABEL
);

has 'token' => ( is => 'ro', default => 0 );
has 'label' => ( is => 'ro' );

sub _attribute_map {+{
	%{shift->SUPER::_attribute_map},
	token => [ CKA_TOKEN, sub{pack('C',shift)} ],
	label => [ CKA_LABEL, sub{shift} ],
}}

1;
