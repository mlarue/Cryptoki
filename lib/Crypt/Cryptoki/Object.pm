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

sub _template_class {
	'Crypt::Cryptoki::Template'
}

sub _build_attributes {
	my ( $self ) = @_;
	my @attr_names = keys %{$self->_template_class->_attribute_map};
	$self->get_attributes(@attr_names);
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

	my $template = $self->_template_class->new;
	my $t = $template->build_template(@attributes);

	my $rv = $self->_fl->C_GetAttributeValue(
		$self->session->id,$self->id,$t
	);
	if ( $rv != CKR_OK ) {
		croak rv_to_str($rv);
	}

	$template->parse($t);
}

1;
