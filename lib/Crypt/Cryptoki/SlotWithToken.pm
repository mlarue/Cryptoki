package Crypt::Cryptoki::SlotWithToken;
use strict;
use Moo;
extends 'Crypt::Cryptoki::Slot';
use Carp;

use Crypt::Cryptoki::Raw qw(rv_to_str CKR_OK);

sub token_info {
        my $self = shift;
        my $info = {};
        my $rv = $self->ctx->_fl->C_GetTokenInfo($self->id, $info);
        if ( $rv != CKR_OK ) {
                croak rv_to_str($rv);
        }
        return $info;
}

1;
