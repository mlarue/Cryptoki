package Crypt::Cryptoki::Template;
use strict;
use Moo;
use Carp;

use Crypt::Cryptoki::Raw qw(
	CKA_CLASS  CKO_PUBLIC_KEY  CKO_PRIVATE_KEY
);

has 'class' => ( is => 'ro' );

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
	my $template = [];

	my $forced = 1;
	unless ( @attributes ) {
		$forced = 0;
		@attributes = keys $map;
	}
	#print STDERR "forced: $forced\n";

	for ( @attributes ) {
		exists $map->{$_} or croak "illegal attribute: $_";
		my $v = $map->{$_};
		#print STDERR ": $_\n";
		if ( defined ( my $value = $self->$_ ) ) {
			if ( $v->[3] and $value =~ s/^0x// ) {
				push @$template, [ $v->[0], $v->[1]->(pack('H*',$value)) ];
			}
			else {
				push @$template, [ $v->[0], $v->[1]->($value) ];
			}
		}
		elsif ( $forced ) {
			# forced attribute, e.g. for GetAttribute templates
			push @$template, [ $v->[0], '' ];
		}
	}

	return $template;
}

sub parse {
	my ( $self, $template, $armored ) = @_;

	my $map = $self->_attribute_map;

	my $result = {};
	for (@$template) {
		my $name = $self->_reverse_attribute_map->{$_->[0]};
		my $v = $map->{$name};
		if ( $armored and $v->[3] ) {
			$result->{$name} = '0x'.unpack('H*',$v->[2]->($_->[1]));
		}
		else {
			$result->{$name} = $v->[2]->($_->[1]);
		}
	}

	return $result;
}

1;
