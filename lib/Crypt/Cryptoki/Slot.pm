package Crypt::Cryptoki::Slot;
use strict;
use Moo;
use Carp;

use Crypt::Cryptoki::Raw qw(rv_to_str CKR_OK);
use Crypt::Cryptoki::Session;

has 'ctx' => ( is => 'ro', required => 1 );
has 'id' => ( is => 'ro', required => 1 );

sub info {
        my $self = shift;
        my $info = {};
        my $rv = $self->ctx->_fl->C_GetSlotInfo($self->id, $info);
        if ( $rv != CKR_OK ) {
                croak rv_to_str($rv);
        }
        return $info;
}

sub token_info {
        my $self = shift;
        my $info = {};
        my $rv = $self->ctx->_fl->C_GetTokenInfo($self->id, $info);
        if ( $rv != CKR_OK ) {
                croak rv_to_str($rv);
        }
        return $info;
}

sub open_session {
        Crypt::Cryptoki::Session->new(slot=>shift,@_);
}

1;
