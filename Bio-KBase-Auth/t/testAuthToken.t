#!/usr/bin/env perl
#
# Test the Authentication Token code
#
# sychan@lbl.gov
# 8/13/2012
# kkeller@lbl.gov August 2016

use strict;

#use lib "../lib/";

use Test::More tests => 27;
#use Test::More;

use Data::Dumper;
use Config::Simple;

BEGIN {
    use_ok( 'Bio::KBase::AuthToken');
}

my %testConfig;
Config::Simple->import_from('./test.cfg', \%testConfig);

my @users = ();

if ( defined $ENV{ $Bio::KBase::AuthToken::TokenEnv }) {
    undef $ENV{ $Bio::KBase::AuthToken::TokenEnv };
}

my %old_config = map { $_ =~ s/authentication\.//; $_ => $Bio::KBase::Auth::Conf{'authentication.' . $_ } } keys %Bio::KBase::Auth::AuthConf;

if ( -e $Bio::KBase::Auth::ConfPath) {
    # clear all the authentication fields that we may care about during testing
    my %new = %old_config;
    foreach my $key ( 'user_id','password','token') {
	$new{$key} = undef;
    }
    Bio::KBase::Auth::SetConfigs( %new);

}

my $authurl=$testConfig{'auth_test.test.authurl'};
my $authBadUrl='https://auth.invalid';
my $validuser=$testConfig{'auth_test.test.validuser'};
my $validpassword=$testConfig{'auth_test.test.validpassword'};
my $validtoken1=$testConfig{'auth_test.test.validtoken1'};
my $validtoken2=$testConfig{'auth_test.test.validtoken2'};
my $invalidtoken=$testConfig{'auth_test.test.invalidtoken'};

note("Using auth server $authurl for testing");

my $at;
ok( $at = Bio::KBase::AuthToken->new(), "Creating empty object with no config");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl), "Creating empty token");
ok( (not defined($at->error_message())), "Making sure empty token doesn't generate error");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'user_id' => $validuser,
    'password' => $testConfig{'auth_test.test.validpassword'}
    ), "Logging in using valid id and password");
ok($at->validate(), "Validating token using valid username/password");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authBadUrl,
    'user_id' => $validuser,
    'password' => $testConfig{'auth_test.test.validpassword'}
    ), "Logging in to bad auth server using valid id and password");
ok(!($at->validate()), "Testing that validating token using valid username/password and invalid auth service fails");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'user_id' => $testConfig{'auth_test.test.validuser'},
    'password' => $testConfig{'auth_test.test.invalidpassword'}
    ), "Logging in using valid account and bad password");
ok(!($at->validate()), "Testing that bad password fails");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'user_id' => $testConfig{'auth_test.test.invaliduser'},
    'password' => $testConfig{'auth_test.test.invalidpassword'}
    ), "Logging in using bad account and bad password");
ok(!($at->validate()), "Testing that bad userid/password fails");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl, 'user_id' => undef, ), "Logging in using undef user_id");
ok(!($at->validate()), "Testing that undef user_id fails");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'token' => $validtoken1,
    ), "Logging in using valid token1");
ok($at->validate(), "Validating valid token1");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'token' => $validtoken2,
    ), "Logging in using valid token2");
ok($at->validate(), "Validating valid token2");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'token' => $invalidtoken,
    ), "Logging in using invalid token");
ok(!($at->validate()), "Testing that bad token fails");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'token' => '',
    ), "Logging in using empty token");
ok(!($at->validate()), "Testing that empty token fails");

#ok( $at = Bio::KBase::AuthToken->new('user_id' => 'kbasetest', 'password' => '@Suite525'), "Logging in using kbasetest account using username/password");
#ok($at->validate(), "Validating token from kbasetest username/password");

note( "Creating settings for testing kbase_config");
Bio::KBase::Auth::SetConfigs('authpath'=>$authurl,"password" =>$validpassword,"user_id" => $validuser);

ok( $at = Bio::KBase::AuthToken->new(), "Creating a new token object for testing kbase_config with password");
ok( $at->user_id() eq $validuser, "Verifying that valid user was read from kbase_config");
ok( $at->validate(), "Verifying that valid user token was acquired properly with userid and password");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl, ignore_kbase_config => 1), "Creating a blank object by ignoring the kbase_config file");
ok( ! defined($at->user_id()), "Verifying that kbase_config was ignored");

if ( -e $Bio::KBase::Auth::ConfPath) {
    # restore old config
    Bio::KBase::Auth::SetConfigs( %old_config);
}


done_testing();

