package Crypt::Cryptoki::Slot;
use strict;
use Moo;
use Carp;

use Crypt::Cryptoki::Raw qw(rv_to_str CKR_OK);
use Crypt::Cryptoki::Session;

has 'ctx' => ( is => 'ro', required => 1 );
has 'id' => ( is => 'ro', required => 1 );
has '_fl' => ( is => 'lazy' );

sub _build__fl {
	shift->ctx->_fl;
}

sub info {
	my $self = shift;
	my $info = {};
	my $rv = $self->_fl->C_GetSlotInfo($self->id, $info);
	if ( $rv != CKR_OK ) {
		croak rv_to_str($rv);
	}
	return $info;
}

sub open_session {
	Crypt::Cryptoki::Session->new(slot=>shift,@_);
}

1;
