package Crypt::Cryptoki::Template;
use strict;
use Moo;
use Carp;

use Crypt::Cryptoki::Raw qw(
	CKA_CLASS  CKO_PUBLIC_KEY  CKO_PRIVATE_KEY
);

has 'class' => ( is => 'ro', default => 0 );

my $class_map = {
	public_key => CKO_PUBLIC_KEY,
	private_key => CKO_PRIVATE_KEY
};
my $reverse_class_map = { reverse %$class_map };

sub _attribute_map {+{
	class => [
		CKA_CLASS, sub{pack('Q',$class_map->{shift()})}, sub{$reverse_class_map->{unpack('Q',@_)}}
	]
}}

sub build_template {
	my ( $self, @attributes ) = @_;

	my $map = $self->_attribute_map;

	unless ( @attributes ) {
		@attributes = keys $map;
	}

	my $template = [];
	for (@attributes) {
		exists $map->{$_} or croak 'illegal attribute';
		my $v = $map->{$_};
		push @$template, [ $v->[0], $v->[1]->( $self->$_ ) ];
	}

	return $template;
}

sub parse_template {
	my ( $self, $template, @attributes ) = @_;

	my $map = $self->_attribute_map;

	unless ( @attributes ) {
		@attributes = keys $map;
	}

	for (@$template) {
		exists $map->{$_} or croak 'illegal attribute';
		my $v = $map->{$_};

		$self->$_->( )
		push @$template, [ $v->[0], $v->[1]->( $self->$_ ) ];
	}

	return $template;
}

1;
