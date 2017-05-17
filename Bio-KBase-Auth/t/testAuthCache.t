#!/usr/bin/env perl
#
# Test the Authentication Token cache code
#
# sychan@lbl.gov
# 8/13/2012
# kkeller@lbl.gov August 2016

use strict;

#use lib "../lib/";

use Test::More tests => 17;
#use Test::More;

use Data::Dumper;
use Config::Simple;

BEGIN {
    use_ok('Bio::KBase::AuthToken');
}

my %testConfig;
Config::Simple->import_from('./test.cfg', \%testConfig);

my $tokenCache={};
my $maxsize=5;

note('Testing cache');
ok(! (Bio::KBase::AuthToken::cache_get($tokenCache,'foo') ), 'Verifying no initial cache entry');
ok(Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'foo','bar'), 'Setting cache entry');
ok(Bio::KBase::AuthToken::cache_get($tokenCache,'foo'), 'Checking cache entry');
ok(Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'foz','baz'), 'Setting second cache entry');
ok(Bio::KBase::AuthToken::cache_get($tokenCache,'foz'), 'Checking cache entry');
ok(! (Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'','baz') ), 'Do not set cache entry without key');
ok(! (Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'baz','') ), 'Do not set cache entry without value');
ok(Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'foo','bar'), 'Resetting existing cache entry');
ok(Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'foo','bar'), 'Resetting existing cache entry');
#ok(Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'foo','bar'), 'Resetting existing cache entry');
#ok(Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'foo','bar'), 'Resetting existing cache entry');
ok(scalar keys (%$tokenCache) == 2, 'Should still be two keys');
ok(Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'foo3','bar'), 'Setting new cache entry');
ok(Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'foo4','bar'), 'Setting new cache entry');
ok(Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'foo5','bar'), 'Setting new cache entry');
# make sure foo6 has newest timestamp
sleep 1;
ok(Bio::KBase::AuthToken::cache_set($tokenCache,$maxsize,'foo6','bar'), 'Setting existing cache entry');
ok(scalar keys (%$tokenCache) <= $maxsize, "Should be fewer or equal than $maxsize keys");

# short expire time
$Bio::KBase::AuthToken::TokenCacheExpire = 1;
sleep 1;
ok(! (Bio::KBase::AuthToken::cache_get($tokenCache,'foo6')), 'Checking cache expiry');

done_testing();

