package Crypt::Cryptoki;

use 5.012005;
use strict;
use warnings;

our $VERSION = '0.01_07';

use Carp;
use Moo;

use Crypt::Cryptoki::Raw qw(rv_to_str CKR_OK);
use Crypt::Cryptoki::Slot;
use Crypt::Cryptoki::SlotWithToken;

has 'module' => ( is => 'ro', required => 1 );
has '_fl' => ( is => 'lazy' );

sub _build__fl {
	my $self = shift;
	my $fl = Crypt::Cryptoki::Raw::load($self->module);
	my $rv = $fl->C_Initialize;
	if ( $rv != CKR_OK ) {
		croak rv_to_str($rv);
	}
	return $fl;
}

sub info {
	my $self = shift;
	my $info = {};
	my $rv = $self->_fl->C_GetInfo($info);
	if ( $rv != CKR_OK ) {
		croak rv_to_str($rv);
	}
	return $info;
}

sub slots {
	my ( $self, %args ) = @_;
	$args{token} ||= 0;
	my $slots = [];
	my $rv = $self->_fl->C_GetSlotList($args{token},$slots);
	if ( $rv != CKR_OK ) {
		croak rv_to_str($rv);
	}
	return $args{token} ?
		map { Crypt::Cryptoki::SlotWithToken->new(ctx=>$self,id=>$_) } @$slots :
		map { Crypt::Cryptoki::Slot->new(ctx=>$self,id=>$_) } @$slots;
}

1;
__END__
=head1 NAME

Crypt::Cryptoki - Perl extension for PKCS#11

=head1 SYNOPSIS

	use Crypt::Cryptoki;

	my $c = Crypt::Cryptoki->new('/usr/lib64/softhsm/libsofthsm.so');

	my $info = $c->info;

	for my $slot ( @{ $c->slots(1) } ) {
		$slot->info;
		$slot->token_info;
	}

	my $session = $c->open_session(
		slot => $slot,
		serial => 1,
		rw => 1
	);

	$session->login_user('1234');

	# or
	$session->login_so('1234');


=head1 DESCRIPTION

This module uses "Crypt::Cryptoki::Raw" to provide a object-oriented access to PKCS#11 instances.

"RSA Security Inc. Public-Key Cryptography Standards (PKCS)"
Please refer to Crypt::Cryptoki::Raw for more information about PKCS#11.



=head2 FUNCTIONS

	new

=head2 METHODS

	info
	slots
	open_session

=head2 EXPORT

None by default.

=head2 TODO

=head1 SEE ALSO

L<http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-11-cryptographic-token-interface-standard.htm>

L<https://www.oasis-open.org/committees/pkcs11>

=head1 AUTHOR

Markus Lauer, E<lt>mlarue@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by Markus Lauer

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.5 or,
at your option, any later version of Perl 5 you may have available.


=cut
