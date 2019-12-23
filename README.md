# Crypt::AnyPasswordHash

Use best installed password encryption available

## Synopsis

    use Crypt::AnyPasswordHash;

    my $password = 'somepassword';

    my Str $hash = hash-password($password);

    if check-password($hash, $password ) {
        # password ok
    }

## Description

This module exports two subroutines `hash-password` and `check-password` which encrypt password and check a provided password against an encryped hash.

The implementation for the subroutines is provided by the first of:

  * [Crypt::SodiumPasswordHash](https://github.com/jonathanstowe/Crypt-SodiumPasswordHash)

  * [Crypt::Argon2](https://github.com/skinkade/p6-crypt-argon2)

  * [Crypt::SodiumScrypt](https://github.com/jonathanstowe/Crypt-SodiumScrypt)

  * [Crypt::Libcrypt](https://github.com/jonathanstowe/Crypt-Libcrypt)

which can be found. `Crypt::Libcrypt` will be installed as a dependency so it will nearly always work but is dependent on the mechanisms provided by the `libcrypt`: with a fairly recent `libcrypt` it will be able to determine and use the best available algorithm, falling back to attempt SHA-512, however if that isn't available it may fall back to DES which is not considered secure enough for production use. You can tell you are getting DES when the hash returned by `hash-password` is only 13 characters long, if this is the case then you should install one of the other providers.

## Installation

If you have a working Rakudo installation, you should be able to install this with *zef* :

     zef install Crypt::AnyPasswordHash

	 # or from a local copy

     zef install .


## Support

If you have any suggestions or patches, please send then to [Github](https://github.com/jonathanstowe/Crypt-AnyPasswordHash/issues)

New hashing providers are welcomed - any new modules should export the subroutines for hashing and verifying.

[Crypt::Bcrypt](https://github.com/skinkade/p6-Crypt-Bcrypt) does work but it needs a small change to be detected.

## Licence

This is free software.

Please see the [LICENCE](LICENCE) file in the distribution

© Jonathan Stowe 2019
