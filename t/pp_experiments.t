use Test::Most 'die';
use Try::Tiny;
use Scalar::Util qw(blessed);

sub string_ref {
	my ( $ref ) = @_;
	$$ref = 'test';
	1;
}

sub array_ref {
	my ( $ref ) = @_;
	@$ref = ( 1, 2, 3, 4 );
	1;
}

sub hash_ref {
	my ( $ref ) = @_;
	%$ref = ( one => 1 );
	1;
}

my $ref;
string_ref(\$ref);
is($ref, 'test', 'string_ref 1');

$ref = 'abc';
string_ref(\$ref);
is($ref, 'test', 'string_ref 2');

$ref = 666;
string_ref(\$ref);
is($ref, 'test', 'string_ref 3');


my $new_called = 0;
my $destroy_called = 0;
package Fred {
	sub new {  $new_called++; bless {}, shift }
	sub DESTROY { $destroy_called++ }
}

{
	my $ref = [];
	array_ref($ref);
	is_deeply($ref, [1,2,3,4], 'array_ref 1');

	$ref = [ Fred->new ];
	array_ref($ref);
	is_deeply($ref, [1,2,3,4], 'array_ref 2');

	my @arr;
	array_ref( \@arr );
	is_deeply(\@arr, [1,2,3,4], 'array_ref 3');

	@arr = ( 8, Fred->new, 2 );
	array_ref( \@arr );
	is_deeply(\@arr, [1,2,3,4], 'array_ref 4');



	$ref = {};
	hash_ref($ref);     
	is_deeply($ref, { 'one' => 1 }, 'hash_ref 1');

	$ref = { fred => Fred->new };
	hash_ref($ref);     
	is_deeply($ref, { 'one' => 1 }, 'hash_ref 2');

	# by incident $ref is also a hash-ref
	$ref = Fred->new;
	hash_ref($ref);     
	is_deeply($ref, { 'one' => 1 }, 'hash_ref 3');
	is( blessed($ref), 'Fred', 'hash_ref 3 (still blessed)' );

	my %hsh;
	hash_ref(\%hsh);     
	is_deeply(\%hsh, { 'one' => 1 }, 'hash_ref 4');

	%hsh = ( its => 'raining' );
	hash_ref(\%hsh);     
	is_deeply(\%hsh, { 'one' => 1 }, 'hash_ref 5');
}

cmp_ok( $new_called, '==', $destroy_called, 'Destruction successful' );



try {
	my @array = qw(a b c);
	hash_ref(\@array);
	is_deeply(\@array, { 'one' => 1 }, 'really? no!');
} catch {
	like($_, qr/^Not a HASH reference/ ,'reference type check: hashref, array')
};

try {
	my $str = "abc";
	hash_ref(\$str);
	is_deeply(\$str, { 'one' => 1 }, 'really? no!');
} catch {
	like($_, qr/^Not a HASH reference/ ,'reference type check: hash_ref, str')
};





try {
	my %hash = ( "a" => 1, "b" => 2 );
	array_ref(\%hash);
	is_deeply(\%hash, [1,2,3,4], 'really? no!');
} catch {
	like($_, qr/^Not an ARRAY reference/ ,'reference type check: arrayref, hash')
};

try {
	my $str = "abc";
	array_ref(\$str);
	is_deeply(\$str, [1,2,3,4], 'really? no!');
} catch {
	like($_, qr/^Not an ARRAY reference/ ,'reference type check: array_ref, str')
};





try {
	my %hash = ( "a" => 1, "b" => 2 );
	string_ref(\%hash);
	is_deeply(\%hash, \'test', 'really? no!');
} catch {
	like($_, qr/^Not a SCALAR reference/ ,'reference type check: string_ref, hash')
};

try {
	my @array = qw(a b c);
	string_ref(\@array);
	is_deeply(\@array, \'test', 'really? no!');
} catch {
	like($_, qr/^Not a SCALAR reference/ ,'reference type check: string_ref, array')
};


done_testing();