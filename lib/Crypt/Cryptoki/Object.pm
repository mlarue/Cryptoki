package Crypt::Cryptoki::Object;
use strict;
use Moo;
use Carp;

use Crypt::Cryptoki::Raw qw(rv_to_str CKR_OK);

has 'session' => ( is => 'ro', required => 1 );
has 'id' => ( is => 'ro', required => 1 );

sub destroy {
        my ( $self ) = @_;
        my $rv = $self->session->slot->ctx->_fl->C_DestroyObject($self->session->id,$self->id);
        if ( $rv != CKR_OK ) {
                croak rv_to_str($rv);
        }
        return 1;
}

1;
