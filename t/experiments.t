use Test::Most 'die';
use Try::Tiny;

use Crypt::Cryptoki::Experiments;

my $ref;
Crypt::Cryptoki::Experiments::string_ref($ref);
is_deeply($ref, \'test', 'string_ref 1');

$ref = \'abc';
Crypt::Cryptoki::Experiments::string_ref($ref);
is_deeply($ref, \'test', 'string_ref 2');

$ref = \666;
Crypt::Cryptoki::Experiments::string_ref($ref);
is_deeply($ref, \'test', 'string_ref 3');


my $new_called = 0;
my $destroy_called = 0;
package Fred {
	sub new {  $new_called++; bless {}, shift }
	sub DESTROY { $destroy_called++ }
}

{
	my $ref;
	#Crypt::Cryptoki::Experiments::array_ref($ref);
	#is_deeply($ref, [1,2,3,4], 'array_ref 1');

	$ref = [ Fred->new ];
	Crypt::Cryptoki::Experiments::array_ref($ref);
	is_deeply($ref, [1,2,3,4], 'array_ref 2');


	Crypt::Cryptoki::Experiments::is_array_ref( $ref );
	my @arr = ( Fred->new, 2 );
	Crypt::Cryptoki::Experiments::is_array_ref(\@arr);
	Crypt::Cryptoki::Experiments::is_array_ref([@arr]);


	Crypt::Cryptoki::Experiments::array_ref( \@arr );
	explain \@arr;
	is_deeply(\@arr, [1,2,3,4], 'array_ref 3');

	$ref = undef;
	Crypt::Cryptoki::Experiments::hash_ref($ref);     
	is_deeply($ref, { 'one' => 1 }, 'hash_ref 1');

	$ref = { fred => Fred->new };
	Crypt::Cryptoki::Experiments::hash_ref($ref);     
	is_deeply($ref, { 'one' => 1 }, 'hash_ref 2');

	$ref = Fred->new;
	# by incident $ref is also a hash-ref
	Crypt::Cryptoki::Experiments::hash_ref($ref);     
	is_deeply($ref, { 'one' => 1 }, 'hash_ref 3');

}

cmp_ok( $new_called, '==', $destroy_called, 'Destruction successful' );

try {
	my @array = qw(a b c);
	Crypt::Cryptoki::Experiments::hash_ref(\@array);
	is_deeply(\@array, { 'one' => 1 }, 'really? no!');
} catch {
	diag $_;
	pass('reference type check: hashref, array')
};

try {
	my $str = "abc";
	Crypt::Cryptoki::Experiments::hash_ref(\$str);
	is_deeply(\$str, { 'one' => 1 }, 'really? no!');
} catch {
	diag $_;
	pass('reference type check: hash_ref, str')
};

try {
	my %hash = ( "a" => 1, "b" => 2 );
	Crypt::Cryptoki::Experiments::array_ref(\%hash);
	is_deeply(\%hash, [1,2,3,4], 'really? no!');
} catch {
	diag $_;
	pass('reference type check: arrayref, hash')
};

try {
	my $str = "abc";
	Crypt::Cryptoki::Experiments::array_ref(\$str);
	is_deeply(\$str, [1,2,3,4], 'really? no!');
} catch {
	diag $_;
	pass('reference type check: array_ref, str')
};

try {
	my %hash = ( "a" => 1, "b" => 2 );
	Crypt::Cryptoki::Experiments::string_ref(\%hash);
	is_deeply(\%hash, \'test', 'really? no!');
} catch {
	diag $_;
	pass('reference type check: string_ref, hash')
};

try {
	my @array = qw(a b c);
	Crypt::Cryptoki::Experiments::string_ref(\@array);
	is_deeply(\@array, \'test', 'really? no!');
} catch {
	diag $_;
	pass('reference type check: string_ref, array')
};

done_testing();