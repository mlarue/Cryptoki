package Crypt::Cryptoki::PrivateKey;
use strict;
use Moo;
extends 'Crypt::Cryptoki::Key';
use Carp;

use Crypt::Cryptoki::Raw qw(rv_to_str CKR_OK CKM_RSA_PKCS NULL_PTR);

sub decrypt {
        my ( $self, $encrypted_text_ref, $encrypted_text_len ) = @_;

        my $rv = $self->session->slot->ctx->_fl->C_DecryptInit(
		$self->session->id, 
		[ CKM_RSA_PKCS, NULL_PTR, 0 ], 
		$self->id
	);
        if ( $rv != CKR_OK ) {
                croak rv_to_str($rv);
        }

	my $decrypted_text = '';
	my $decrypted_text_len = -1;

        $rv = $self->session->slot->ctx->_fl->C_Decrypt(
		$self->session->id, 
		$$encrypted_text_ref,
		$encrypted_text_len,
		$decrypted_text,
		$decrypted_text_len
	);
        if ( $rv != CKR_OK ) {
                croak rv_to_str($rv);
        }

        return ( \$decrypted_text, $decrypted_text_len );
}

1;
