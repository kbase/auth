package Bio::KBase::AuthToken;

use strict;
use warnings;
use JSON;
use LWP::UserAgent;
use Digest::SHA qw(sha256_base64);
use Crypt::OpenSSL::RSA;
use Convert::PEM;
use MIME::Base64;
use URI;
use POSIX;
use DateTime;
use Data::Dumper;

use Bio::KBase::Auth;

# We use Object::Tiny::RW to generate getters/setters for the attributes
# and save ourselves some tedium
use Object::Tiny::RW qw {
    error_message
    user_id
    password
};

# Pull the INI files based configs in
# use a typeglob to alias it
our %Conf;
*Conf = \%Bio::KBase::Auth::AuthConf;

our $VERSION = $Bio::KBase::Auth::VERSION;

# Tokens (last time we checked) had a 24 hour lifetime, this value can be
# used to add extra time to the lifetime of tokens. The unit is seconds.
# This can be be overridden  with a parameter passed into the validate() function.
our $token_lifetime = 0;
our @attrs = ( 'user_id', 'token', 'password',);

our $LWPTimeout = 5;

# Some hashes to cache tokens and Token Signers we have seen before
our $SignerCache;
our $SignerCacheSize = exists($Conf{'authentication.signer_cache_size'}) ?
                              $Conf{'authentication.signer_cache_size'} : 12;
# For long running processes, like a server, we use a fixed length cache
# to limit the number of entries we cache. The token cache only stores
# the user_id and sha256 of the token, and not the actual token
our $TokenCache;
our $TokenCacheSize = exists($Conf{'authentication.token_cache_size'}) ?
                             $Conf{'authentication.token_cache_size'} : 2000;

# Expire cache entries which are older than this
our $TokenCacheExpire = exists($Conf{'authentication.token_cache_expire'}) ?
                             $Conf{'authentication.token_cache_expire'} : 5*60;

# Pickup the cache hashing salt from configs
our $CacheKeySalt = exists($Conf{'authentication.cache_salt'}) ?
                           $Conf{'Authentication.cache_salt'} : "NaCl";

# If enabled, create some shared memory hashes for our cache.
# Make them only readable/writeable by ourselves
if ($Conf{'authentication.shm_cache'}) {
    die 'not supported!';
}

$TokenCache = {};
$SignerCache = '';

# This is the name of the environment variable that contains a
# pregenerated token
our $TokenEnv = exists($Conf{'authentication.tokenvar'}) ?
    $Conf{'authentication.tokenvar'} : "KB_AUTH_TOKEN";

# Your typical constructor - takes a hash that specifies the initial values to
# plug into the object.
# A special attribute is "ignore_kbase_config", if that it set then we will not bother
# trying to read the ~/.kbase_config file
sub new {
    my $class = shift;

    # Don't bother with calling the Object::Tiny::RW constructor,
    # since it doesn't do anything except return a blessed empty hash
    my $self = $class->SUPER::new(
        'token' => undef,
        'error_message' => undef,
        @_
    );

    $self->{'auth_svc'} = $Bio::KBase::Auth::AuthorizePath
        unless ($self->{'auth_svc'});

    eval {
	# make ignore_kbase_config an alias for ignore_authrc if it isn't specified
	if ( !exists( $self->{'ignore_kbase_config'}) &&
	     exists( $self->{'ignore_authrc'})) {
	    $self->{'ignore_kbase_config'} = $self->{'ignore_authrc'};
	}

	# Do we have any default attributes from the $Conf hash?
	my %c = %Bio::KBase::Auth::AuthConf;
	my $def_attr = scalar( grep { exists( $c{ 'authentication.'.$_}) } @attrs);
			    
	# If we were given a token, try set that using the formal setter
	# elsif we have appropriate login credentials, try to get a
	# token
	if ($self->{'token'}) {
	    $self->token( $self->{'token'});
	    $self->validate();
	} elsif ($self->{'user_id'} && $self->{'password'} ) {
	    $self->get();
	} elsif ( defined( $ENV{$TokenEnv})) {
	    $self->token($ENV{$TokenEnv});
	} elsif (! $self->{'ignore_kbase_config'} && $def_attr ) {
	    # If we get a token, use that immediately and ignore the rest,
	    # otherwise set the other attributes and fetch the token
	    if (exists( $c{'authentication.token'})) {
		$self->token( $c{'authentication.token'});
		$self->validate();
	    } else {
		foreach my $attr ( @attrs) {
		    if (exists( $c{ 'authentication.'.$attr })) {
			$self->{ $attr } = $c{ 'authentication.'.$attr };
		    }
		}
		$self->get();
	    }
	}
    };
    if ($@) {
	$self->error_message("Failed to acquire token: $@");
    }
    return($self);
}

# fetch something from the cache
# cache_get( cache, key)
# cache is a reference to the string used to store the cache
# key is the value of the object to compare to see if there is
#  a cache hit
# returns true or false for if the key is found
sub cache_get {
    my($cache, $key) = @_;

    unless ($key)
    {
        warn 'Must supply a key';
        return undef;
    }
    
    # Convert the key to a salted sha256 hash
    my $keyhash = sha256_base64( $key.$CacheKeySalt);
    
    if ($cache->{$keyhash} and (time() - $cache->{$keyhash}{'timestamp'} < $TokenCacheExpire))
    {
        # update last seen time: the old Perl code did this
        # but the current Python code does not
        $cache->{$keyhash}{'timestamp'} = time();
        return $cache->{$keyhash}{'value'};
    }

    return undef;
}

# cache_set( cache, maxsize, key, value)
# cache is a hashref used for the cache
# maxrows is the maximum number of rows that can be in the cache
# key is the value of the object to use for future comparison
# value is the value to be stored there - it is expected to be a scalar
# The cache is ordered by last seen time and anything more than the
# maxrows is dropped
# returns the value stored if successful
sub cache_set {
    my($cache, $maxsize, $key, $value) = @_;
    unless ($key and $value)
    {
        warn 'Must supply a key and a value';
        return undef;
    }

    my($keyhash) = sha256_base64( $key.$CacheKeySalt);
    $cache->{$keyhash} = {
        key =>  $keyhash,
        value   =>  $value,
        timestamp   =>  time(),
        };

    # still to do: reduce cache if too many keys
    if ( (scalar keys(%$cache)) > $maxsize)
    {
        my $deletesize = int($maxsize/2)-1;

#        warn 'cache size ' . scalar keys (%$cache) . ", need to reduce cache, deleting $deletesize keys";

        # sort by timestamp
        my @sortedKeys = sort {
            $cache->{$a}{'timestamp'} <=> $cache->{$b}{'timestamp'} 
            } keys %$cache;
        my @deleteKeys = @sortedKeys[0..$deletesize];
# this may be too unreadable
        my @deletedKeys = delete @{$cache}{@deleteKeys};
# more readable but deleting from hash slice is probably faster
#        foreach my $deleteKey (@deleteKeys)
#        {
#            delete $cache->{$deleteKey};
#        }
    }

    return $value;
}

# getter/setter for token, if we are given a token, parse it out
# and set the appropriate attributes 
sub token {
    my $self = shift @_;
    my $token = shift;
    my $url = $self->{'auth_svc'};

    unless($token) {
	return( $self->{'token'});
    }

    # parse out token and set user_id
    eval {
	$self->{'token'} = $token;

# Use KBase auth service to get user
	# Check the token cache first
	my $cached_userid = cache_get( $TokenCache, $self->{'token'});
# need to figure out why it's comparing the username
# (but could get from server if needed anyway)
	if ( $cached_userid and $cached_userid eq $self->{'user_id'}) {
            return($token);
        }
	my $res = $self->_auth_svc_req( 'user_id'=>$self->{'user_id'},
            'password'=>$self->{'password'}, 'fields' => 'token');
	unless ($res->{'user_id'}) {
	    die "No user_id returned by service";
        }
#	$json = $self->_SquashJSONBool($json);
        $self->{'user_id'} = $res->{'user_id'};
        # write the cache
        cache_set( $TokenCache, $TokenCacheSize, $self->{'token'}, $self->{'user_id'});
    };

    if ($@) {
	$self->error_message("Invalid token: $@");
	return( undef);
    } else {
	$self->{'error_message'} = undef;
	return( $token);
    }
}

# Get a nexus token, using user_id, password
# Parameters looked for within $self:
# user_id => user name recognized on globus online for login
# password => Globus online password
# Throws an exception if either invalid set of creds or failed login

sub get {
    my $self = shift @_;
    my %p = @_;
    my $res;

    eval {
	if ($p{'user_id'}) {
	    $self->user_id($p{'user_id'});
	}
	if ($p{'password'}) {
	    $self->password($p{'password'});
	}

	# Make sure we have the right combo of creds
	unless ($self->{'user_id'} && $self->{'password'}) {
	    die("Need user_id and password to be defined.");
	}
	
	$res = $self->_auth_svc_req( 'user_id'=>$self->{'user_id'},
            'password'=>$self->{'password'}, 'fields' => 'token');
	unless ($res->{'token'}) {
	    die "No token returned by service";
	}
        # write the cache
        cache_set( $TokenCache, $TokenCacheSize, $res->{'token'}, $self->{'user_id'});
    };
    if ($@) {
	$self->{'token'} = undef;
	$self->{'user_id'} = undef;
        # should this set error_message instead of dieing?
	die "Failed to get auth token: $@";
    } else {
	return($self->token( $res->{'token'}));
    }
}

# Function that returns if the token is valid or not
# optionally accepts hash as parameters
#
sub validate {

    my $self = shift;
    my %p = @_;
    my $url = $self->{'auth_svc'};

    unless ($self->{'token'})
    {
        $self->{'error_message'} = 'No token provided';
        return(undef);
    }
    
# Use KBase auth service to get user
# todo: check local cache
    eval {
	# Check the token cache first
	my $cached_userid = cache_get( $TokenCache, $self->{'token'});
# need to figure out why it's comparing the username
# (but could get from server if needed anyway)
	if ( $cached_userid and $cached_userid eq $self->{'user_id'}) {
            return(1);
	} else {
	my $res = $self->_auth_svc_req( 'token'=>$self->{'token'},
            'fields' => 'token');
	unless ($res->{'token'}) {
	    die "No token returned by service";
        }
            # write the cache
            cache_set( $TokenCache, $TokenCacheSize, $self->{'token'}, $self->{'user_id'});
	}
    };

    if ($@) {
	$self->{'error_message'} = "Failed to query KBase auth: $@";
        return(undef);
    } else {
	return(1);
    }
}

sub _auth_svc_req {
    my $self = shift @_;
    my %p = @_;
    my $url = $self->{'auth_svc'};

    # $p{'fields'} should have only one field

    my $json;
    eval {

        my $client = LWP::UserAgent->new();
	$client->timeout($LWPTimeout);
        my $content={
            'user_id'   =>  $p{'user_id'},
            'password'  =>  $p{'password'},
            'fields'    =>  $p{'fields'},
            };
        if ($p{'token'})
        {
            $content = {
                'token'   =>  $p{'token'},
                'fields'    => $p{'fields'},
            };
        }
	my $response = $client->post($url, $content);
	unless ($response->is_success) {
	    die $response->status_line;
	}
	$json = decode_json( $response->content());
#	$json = $self->_SquashJSONBool($json);
    };
    if ($@) {
	die "Failed to query KBase auth: $@";
    } else {
	return($json);
    }

}

1;

__END__

=pod

=head1 Bio::KBase::AuthToken

Token object for KBase tokens.

=head2 Examples

   # Acquiring a new token when you have username/password credentials
   my $token = Bio::KBase::AuthToken->new( 'auth_svc'=>$authurl, 'user_id' => 'mrbig', 'password' => 'bigP@SSword');

   # or if you have a token in the variable $token, you can use
   my $token2 = Bio::KBase::AuthToken->new( 'auth_svc'=>$authurl, 'user_id' => 'mrbig', 'token' => $token);

   # If you have a token in the shell environment variable $KB_AUTH_TOKEN you can
   # just instantiate an object with no parameters and it will use that as if it
   # were passed in as a token => %ENV{ KB_AUTH_TOKEN } among the params. This
   # will also work if there are no legit combinations of credential information
   # passed in
   my $tok = Bio::KBase::AuthToken->new( token => 'very long token string');
   # is the same as
   $ENV{ 'KB_AUTH_TOKEN'} = 'very long token string';
   my $tok = Bio::KBase::AuthToken->new()
   
   # any parameters for a credential/login that can be passed in to the new() method can
   # be put in the [authentication] section of the INI file specified in
   # $Bio::KBase::Auth::ConfPath ( defaults to ~/.kbase_config ) will be used to
   # initialize the object unless the ignore_kbase_config is set to a true value in the
   # call to new()
   # 
   # This is triggered by not providing any parameters to the new() method and not
   # having a $ENV{ KB_AUTH_TOKEN } defined.
   #
   # if ~/.kbase_config contains:
   # [authentication]
   # user_id=figaro
   # password=mamamia_mamamia
   #
   # Then the constructor will try to acquire a token with the user_id and password
   # settings provided.
   # Currently this library recognizes user_id,token,password,auth_svc
   #
   # To login as jqpublic with an ssh key in ~jqpublic/.ssh/id_kbase that has the passphrase
   # "MostlySecret" you can set this in the .kbase_config file:
   # [authentication]
   # user_id=jqpublic
   # keyfile=/Users/jqpublic/.ssh/id_kbase
   # keyfile_passphrase=MostlySecret
   # 
   # and then execute the following
   my $token4 = Bio::KBase::AuthToken->new();

   # To disable this and just return an empty token object user
   my $token5 = Bio::KBase::AuthToken->new( ignore_kbase_config => 1 );

   # If you have a token in $tok, and wish to check if it is valid
   my $token3 = Bio::KBase::AuthToken->new( 'token' => $tok);
   if ($token3->validate()) {
       # token is legit
       my $user_id = $token3->user_id();

       # acquiring a full user profile once you have a token
       my $profile = new Bio::KBase::AuthUser->new;
       $profile->get( $token3->token());

   } else {
       die "Begone, evildoer!\n";
   }

=head2 Class Variables

=over

=item B<%Conf>

This contains the configuration directives from the user's ~/.kbase_config under the section header "authentication". All the config settings can be accessed via $Bio::KBase::AuthUser::Conf{ 'authentication.NAME'}, where NAME is found in the config file under the section heading "authentication".

=item B<@trust_token_signers>

An array that contains prefixes for trusted signing URLs in the SigningSubject field of tokens.

=item B<$token_lifetime>

Additional seconds to add to the expiration time of tokens. Tokens currently issued with a default 24 hour lifetime, but modifying this value will change when the validate() function will no longer accept the token. The units are in seconds.

=item B<@attrs>

List of strings that enumerate the attributes allowed to be read from the B<.kbase_config> file.

=item B<$VERSION>

This is the version string (pulled from the Bio::KBase::Auth module)

=item B<$TokenCache,$SignerCache>

These are CSV formatted strings for the Token and TokenSigner caches that contain 3 fields: last seen time, hash key, value

The last seen time is the output from time() when the record was last request or loaded

The hash key is a salted SHA256 hash of the token string (for the TokenCache) or the Signer URL (for the SignerCache)

The value is the username associated with the token (for TokenCache) or the JSON document at the Signer URL (for the SignerCache)

Entries are not expired due to any TTL, but are pushed out based on their last access time.

The cache is searched and timestamps are updated using perl regex functions to achieve good performance. New entries are added and deleted using split(), sort() and join() for performance as well. When the Shared memory caching option is enabled ( with authentication.shm_cache in the config file), this string is tied into an IPC::Shareable memory region.

=item B<$TokenCacheSize,$SignerCacheSize> integer

This is maximum the number of token validations or signer URL JSON docs that are kept in the cache. Each time that a new token/signer is added, the entries are sorted in descending time order, and any entries above this number are dropped. This can be configured via the authentication.token_cache_size and authentication.signer_cache_size directive.

=item B<$CacheKeySalt>

String used to salt the sha256 hash calculated for cache keys. Set using authentication.cache_salt

=item B<$TokenVar>

Shell environment variable that may contain a token to be used as a default token value, defaults to "KB_AUTH_TOKEN". This environment variable can be overridden by authentication.tokenvar in the .kbase_config file

=item B<$AuthzDB>

MongoDB::Database reference that is initialized by the authentication.authzdb value from the kbase_config file. The value in the configuration must refer to an existing database in the MongoDB instance referenced by $Bio::KBase::Auth::MongoDB. If authentication.authzdb is declared but the authentication.mongodb setting is invalid, or if the database does not exist, then an exception will be thrown at module load time. Do not set this unless you really know what you are doing.

=back

=head2 Instance Variables

=over

=item B<user_id> (string)

REQUIRED Userid of the associated with the token

=item B<token> (string)

A string containing a signed assertion from the Globus Nexus service. Here is an example:

un=sychan|clientid=sychan|expiry=1376425658|SigningSubject=https://graph.api.go.sandbox.globuscs.info/goauth/keys/da0a4e96-e22a-11e1-9b09-1231381bc4c2|sig=88cb32eae2782452817f106a2ce8cf9215f3356ce123d43395a5c99c5ec4184eaf5d70111124a06cf9267e5340f1d06b9258cf2e70e8000000000000000000000000000000583c68755de5453b4b019ebf3d7d4547778ef7d6322f2ba8f42d370bbce4b693ef7a9b3c7be3c6970132e72c654e3274afab9ea39ba9724383f1594

It is a series of name value pairs:

   un = username
   clientid = Globus Nexus client id
   expiry = time when the token was issued
   SigningSubject = url to the public key used to verify the signature
   sig = RSA sha256 signature hash

=item B<password> (string)

The password used to acquire token (if provided). Note that it is not possible to pull down the password from the authentication service.

=item B<client_secret> (string)

An unencrypted openssh formatted RSA private key string used for authentication

=item B<keyfile> (string)

File containing a B<client_secret> (typically something like ~user/.ssh/id_rsa). This must be readable by the effective UID of the running process. If the file contains an encrypted passphrase then the B<keyfile_passphrase> must also be specified. Private keys can be created using the ssh-keygen command (for example "ssh-keygen -t rsa -b 1024 -f kbase_rsa")

=item B<keyfile_passphrase> (string)

The passphrase used to decrypt the RSA private specified in B<keyfile>. See the ssh-keygen man page for information and setting/clering the passphrase.

=item B<sshagent_keys> (hashref keynames => ssh_agent_keys)

Hashref with keyname => rsa_sshkey pairs. The keyname is generated by ssh-agent and is the path to the private. Only RSA keys are exposed.

=item B<sshagent_keyname> (string)

String specifying which key in the sshagent to use for authentication. Must match one of the keys in sshagent_keys - format is typically the path to the private key

=item B<error_message> (string)

contains error messages, if any, from most recent method call.

=back

=head2 Methods

=over

=item B<new>()

returns a Bio::KBase::AuthToken reference. Optionally pass in hash params to initialize attributes. If we have enough attributes to perform a login either a token, or (user_id,password) or (user_id,client_secret) then the library will try to acquire a new token from Globus Nexus. If no parameters are given, then the library will look for a readable INI file in ~/.kbase_config and extract the attributes that match from @Bio::KBase::AuthToken::attrs into the new token an attempt to fetch a token from the Globus Online service. If you wish to short circuit the .kbase_config file, you can pass in a ignore_kbase_config => 1 as a parameter to new()

   Examples:

   # Acquiring a new token when you have username/password credentials
   my $token = Bio::KBase::AuthToken->new( 'user_id' => 'mrbig', 'password' => 'bigP@SSword');

   # or if you have an SSH private key in the string $rsakey

   my $token2 = Bio::KBase::AuthToken->new( 'user_id' => 'mrbig', 'client_secret' => $rsakey);

   # you have an rsa key in the file /home/mrbig/.ssh/id_rsa and wish to use it for authentication
   my $token3 = Bio::KBase::AuthToken->new( 'user_id' => 'mrbig', 'keyfile' => '/home/mrbig/.ssh/id_rsa');
   
   # Whoops, turns out it was encrypted
   my $token3 = Bio::KBase::AuthToken->new( 'user_id' => 'mrbig', 'keyfile' => '/home/mrbig/.ssh/id_rsa',
                                            'keyfile_passphrase' => 'L33Tp@55word');


=item B<user_id>()

returns the user_id associated with the token, if any. If a single string value is passed in, it will be used to set the value of the user_id

=item B<validate>()

attempts to verify the signature on the token, and returns a boolean value signifying whether the token is legit. If the value in the token attribute is a legitimate kbase session ID hash and a session database has been enabled (by the $AuthzDB database handle), the session ID will be replaced by the associated token, and then validated - this is only relevant for installations where the session service has been enabled.


=back

=cut
