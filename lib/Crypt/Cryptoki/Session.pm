package Crypt::Cryptoki::Session;
use strict;
use Moo;
use Carp;

use Crypt::Cryptoki::Raw qw(rv_to_str CKR_OK CKU_USER CKF_SERIAL_SESSION CKF_RW_SESSION); 

has 'slot' => ( is => 'ro', required => 1 );
has 'serial' => ( is => 'ro', default => 1 );
has 'rw' => ( is => 'ro' );
has 'id' => ( is => 'lazy' );

sub _build_id {
	my $self = shift;
	$self->open;
}

sub open {
        my ( $self ) = @_;

        my $flags = 0;
        $flags |= CKF_SERIAL_SESSION if $self->serial;
        $flags |= CKF_RW_SESSION if $self->rw;

        my $session = -1;
        my $rv = $self->slot->ctx->_fl->C_OpenSession($self->slot->id, $flags, $session);
        if ( $rv != CKR_OK ) {
                croak rv_to_str($rv);
        }
	return $session;
}

sub login {
        my ( $self, $user, $pin ) = @_;
        my $rv = $self->slot->ctx->_fl->C_Login($self->id, $user, $pin);
        if ( $rv != CKR_OK ) {
                croak rv_to_str($rv);
        }
        return 1;
}

sub login_user {
        my ( $self, $pin ) = @_;
	$self->login(CKU_USER,$pin);
}
 
sub login_so {
        my ( $self, $pin ) = @_;
	# TODO
	$self->login(CKU_USER,$pin);
}
 
1;
