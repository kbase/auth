#!/usr/bin/env perl
#
# Test the AuthUser class
# sychan@lbl.gov
# 8/13/2012
#

use lib "../lib/";
use lib "lib";
use HTTP::Daemon;
use HTTP::Request;
use LWP::UserAgent;
use JSON;
use Test::More tests => 25;


BEGIN {
    use_ok( Bio::KBase::AuthUser);
    use_ok( Bio::KBase::AuthToken);
}


ok( $at = Bio::KBase::AuthToken->new('user_id' => 'kbasetest', 'password' => '@Suite525'), "Acquiring kbasetest user token using username/password");
ok($at->validate(), "Validating token from kbasetest username/password");
ok($au = Bio::KBase::AuthUser->new(), "Creating a new AuthUser object with no credentials");
ok(!($au->get()), "Trying to fetch user profile without credentials, should fail.");
note( $au->error_message());
ok($au->get(token => $at->token), "Trying to fetch user profile using legitimate token for kbasetest, should succeed.");
is($au->user_id(), "kbasetest", "Verifying that the user record acquired is for the kbasetest user");
is($au->email(), 'sychan@lbl.gov', "Verifying that email address is sychan\@lbl.gov");
ok($au2 = Bio::KBase::AuthUser->new( 'token' => $at->token), "Creating a new AuthUser object initialized with token");
is($au2->user_id(), "kbasetest", "Verifying that the user record acquired is for the kbasetest user");

# Generate random string for testing custom field settings
srand(time);
$random = join( ":", map {int rand(1000000000);} (0..5));
note( "New random numbers are $random");
ok( $au->{"random_numbers"} ne $random, "Verifying that current \"random_numbers\" attribute is not equal to new random numbers.");
ok($au->update('email' => 'sychan@nersc.gov', "random_numbers" => $random), "Setting new email address and random_number field");
is($au->email(), 'sychan@nersc.gov', "Verifying that new email address has been set in current record");
is($au->{'random_numbers'},$random, "Verifying that new random number is set in current record");
ok($au2 = Bio::KBase::AuthUser->new(), "Creating a second AuthUser object to verify changes");
ok($au2->get(token =>$at->token, nocache => 1), "Trying to fetch user profile to new object");
ok($au2 != $au, "Verifying that second reference doesn't point to the same object as first");
is($au->{'random_numbers'},$au2->{'random_numbers'}, "Comparing random numbers for equality in newly fetched record.");
is($au->{'email'},$au2->{'email'}, "Comparing email addresses for equality in newly fetched record.");
ok($au2->update('email' => 'sychan@lbl.gov'), "Setting email back to original value in second object");
is($au2->email(), 'sychan@lbl.gov', "Verifying email is set back to original value");
ok($au->email() ne $au2->email, "Email addresses should not match between 2 profile records.");
ok($au->get(), "Updating first object");
ok($au->email() eq $au2->email, "Email addresses should now match.");

done_testing();

