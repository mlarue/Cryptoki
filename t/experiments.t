use Test::Most;
use Try::Tiny;
use Scalar::Util qw(blessed);
use Devel::Peek;

use Crypt::Cryptoki::Experiments qw(string_ref array_ref hash_ref);

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
	sub new { $new_called++; my $class = shift; bless { @_ }, $class }
	sub DESTROY { $destroy_called++ }
}

{
	my $ref = [];
	array_ref($ref);
	is_deeply($ref, [1,2,3,4], 'array_ref 1');

	$ref = [ Fred->new ];
	#Dump($ref);
	array_ref($ref);
	#Dump($ref);
	is_deeply($ref, [1,2,3,4], 'array_ref 2');

	my @arr;
	array_ref( \@arr );
	is_deeply(\@arr, [1,2,3,4], 'array_ref 3');

	@arr = ( 8, Fred->new, 2 );
	#Dump(\@arr);
	array_ref( \@arr );
	#Dump(\@arr);
	is_deeply(\@arr, [1,2,3,4], 'array_ref 4');



	$ref = {};
	hash_ref($ref);     
	is_deeply($ref, { 'one' => 1 }, 'hash_ref 1');

	$ref = { fred => Fred->new };
	#Dump($ref);
	hash_ref($ref); 
	#Dump($ref);
	is_deeply($ref, { 'one' => 1 }, 'hash_ref 2');

	# by incident this blessed $ref is also a hash-ref
	$ref = Fred->new( blut => 'wurst' );
	#Dump($ref);
	hash_ref($ref);
	#Dump($ref);
	is_deeply($ref, { 'one' => 1 }, 'hash_ref 3');
	is( blessed($ref), 'Fred', 'hash_ref 3 (still blessed)' );

	#$ref = undef;
	#$ref->DESTROY;

	my %hsh;
	hash_ref(\%hsh);     
	is_deeply(\%hsh, { 'one' => 1 }, 'hash_ref 4');

	%hsh = ( its => 'raining' );
	hash_ref(\%hsh);     
	is_deeply(\%hsh, { 'one' => 1 }, 'hash_ref 5');
}

#       got                    expected
cmp_ok( $destroy_called, '==', $new_called, 'Destruction successful' );



try {
	my @array = qw(a b c);
	hash_ref(\@array);
	is_deeply(\@array, { 'one' => 1 }, 'really? no!');
} catch {
	like($_, qr/not a HASH reference/ ,'reference type check: hashref, array')
};

try {
	my $str = "abc";
	hash_ref(\$str);
	is_deeply(\$str, { 'one' => 1 }, 'really? no!');
} catch {
	like($_, qr/not a HASH reference/ ,'reference type check: hash_ref, str')
};





try {
	my %hash = ( "a" => 1, "b" => 2 );
	array_ref(\%hash);
	is_deeply(\%hash, [1,2,3,4], 'really? no!');
} catch {
	like($_, qr/not an ARRAY reference/ ,'reference type check: arrayref, hash')
};

try {
	my $str = "abc";
	array_ref(\$str);
	is_deeply(\$str, [1,2,3,4], 'really? no!');
} catch {
	like($_, qr/not an ARRAY reference/ ,'reference type check: array_ref, str')
};





try {
	my %hash = ( "a" => 1, "b" => 2 );
	string_ref(\%hash);
	is_deeply(\%hash, \'test', 'really? no!');
} catch {
	like($_, qr/not a SCALAR reference/ ,'reference type check: string_ref, hash')
};

try {
	my @array = qw(a b c);
	string_ref(\@array);
	is_deeply(\@array, \'test', 'really? no!');
} catch {
	like($_, qr/not a SCALAR reference/ ,'reference type check: string_ref, array')
};

done_testing();