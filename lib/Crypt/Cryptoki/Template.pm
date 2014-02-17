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
		CKA_CLASS, 
		sub{pack('Q',$class_map->{$_[0]})}, 
		sub{$reverse_class_map->{unpack('Q',$_[0])}}
	]
}}

sub _reverse_attribute_map {
	my $self = shift;
	+{ map { $self->_attribute_map->{$_}[0] => $_ } keys %{$self->_attribute_map} }
}; 

sub build {
	my ( $self, @attributes ) = @_;

	my $map = $self->_attribute_map;

	unless ( @attributes ) {
		@attributes = keys $map;
	}

	my $template = [];
	for (@attributes) {
		exists $map->{$_} or croak "illegal attribute: $_";
		my $v = $map->{$_};
		#print STDERR $_, ' ', $self->$_, ' ', unpack('H*',$v->[1]->($self->$_)), "\n";
		push @$template, [ $v->[0], $v->[1]->( $self->$_ ) ];
	}

	return $template;
}

sub parse {
	my ( $self, $template ) = @_;

	my $map = $self->_attribute_map;

	my $result = {};
	for (@$template) {
		my $name = $self->_reverse_attribute_map->{$_->[0]};
		$result->{$name} = $map->{$name}->[2]->($_->[1]);
	}

	return $result;
}

1;
