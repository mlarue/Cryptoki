package Crypt::Cryptoki::Object;
use strict;
use Moo;
use Carp;
use List::MoreUtils qw(zip);

use Crypt::Cryptoki::Raw qw(rv_to_str CKR_OK);

has 'session' => ( is => 'ro', required => 1 );
has 'id' => ( is => 'ro', required => 1 );
has 'attributes' => ( is => 'lazy' );
has '_fl' => ( is => 'lazy' );

sub _build__fl {
	shift->session->slot->ctx->_fl;
}

sub _attribute_map {{
}}

sub _build_attributes {
	my ( $self ) = @_;
	my @attr_names = keys %{$self->_attribute_map};
	my @attrs = $self->get_attributes(@attr_names);
	+{ zip @attr_names, @attrs };
}

sub hex_attributes {
	my ( $self ) = @_;
	my $attrs = $self->attributes;
	+{ map { $_ => unpack('H*',$attrs->{$_}) } keys %$attrs };
}

sub destroy {
	my ( $self ) = @_;
	my $rv = $self->_fl->C_DestroyObject($self->session->id,$self->id);
	if ( $rv != CKR_OK ) {
		croak rv_to_str($rv);
	}
	1;
}

sub get_attributes {
	my ( $self, @attributes ) = @_;

	my @get_attributes_template;
	for (@attributes) {
		exists $self->_attribute_map->{$_} or croak 'illegal attribute';
		push @get_attributes_template, [ $self->_attribute_map->{$_}, '' ];
	}

	my $rv = $self->_fl->C_GetAttributeValue(
		$self->session->id,$self->id,\@get_attributes_template
	);
	if ( $rv != CKR_OK ) {
		croak rv_to_str($rv);
	}

	map { ''.$_->[1] } @get_attributes_template;
}

1;
