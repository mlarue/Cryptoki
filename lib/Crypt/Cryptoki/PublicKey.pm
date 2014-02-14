package Crypt::Cryptoki::PublicKey;
use strict;
use Moo;
extends 'Crypt::Cryptoki::Key';
use Carp;

use Crypt::Cryptoki::Raw qw(rv_to_str CKR_OK CKM_RSA_PKCS NULL_PTR);

sub encrypt {
        my ( $self, $plain_text_ref, $plain_text_len ) = @_;

        my $rv = $self->session->slot->ctx->_fl->C_EncryptInit(
		$self->session->id, 
		[ CKM_RSA_PKCS, NULL_PTR, 0 ], 
		$self->id
	);
        if ( $rv != CKR_OK ) {
                croak rv_to_str($rv);
        }

	my $encrypted_text = '';
	my $encrypted_text_len = -1;

        $rv = $self->session->slot->ctx->_fl->C_Encrypt(
		$self->session->id, 
		$$plain_text_ref,
		$plain_text_len,
		$encrypted_text,
		$encrypted_text_len
	);
        if ( $rv != CKR_OK ) {
                croak rv_to_str($rv);
        }

        return ( \$encrypted_text, $encrypted_text_len );
}

1;
