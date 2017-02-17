#!perl -T

use Test::More tests => 2;

BEGIN {
    use_ok( 'Bio::KBase::Auth' ) || print "Bail out!\n";
    use_ok( 'Bio::KBase::AuthToken' ) || print "Bail out!\n";
}

note( "Testing Bio::KBase::Auth $Bio::KBase::Auth::VERSION, Perl $], $^X" );
