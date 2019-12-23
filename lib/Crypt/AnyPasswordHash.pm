use v6;

=begin pod

=head1 NAME

Crypt::AnyPasswordHash - use best installed password encryption

=head1 SYNOPSIS

=begin code

use Crypt::AnyPasswordHash;

my $password = 'somepassword';

my Str $hash = hash-password($password);

if check-password($hash, $password ) {
    # password ok
}

=end code

=head1 DESCRIPTION

This module exports two subroutines C<hash-password> and C<check-password>
which encrypt password and check a provided password against an encryped hash.

The implementation for the subroutines is provided by the first of:

=item L<Crypt::SodiumPasswordHash|https://github.com/jonathanstowe/Crypt-SodiumPasswordHash>

=item L<Crypt::Argon2|https://github.com/skinkade/p6-crypt-argon2>

=item L<Crypt::SodiumScrypt|https://github.com/jonathanstowe/Crypt-SodiumScrypt>

=item L<Crypt::Libcrypt|https://github.com/jonathanstowe/Crypt-Libcrypt>

which can be found.  C<Crypt::Libcrypt> will be installed as a dependency so it
will nearly always work but is dependent on the mechanisms provided by the C<libcrypt>:
with a fairly recent C<libcrypt> it will be able to determine and use the best
available algorithm, falling back to attempt SHA-512, however if that isn't available
it may fall back to DES which is not considered secure enough for production use. You
can tell you are getting DES when the hash returned by C<hash-password> is only 13
characters long, if this is the case then you should install one of the other providers.

=end pod


module Crypt::AnyPasswordHash {
}

sub EXPORT() {
    my &hash-password;
    my &check-password;

    if (try require ::('Crypt::SodiumPasswordHash') <&sodium-hash &sodium-verify>) !=== Nil {
        &hash-password = &sodium-hash;
        &check-password = &sodium-verify
    }
    elsif (try require ::('Crypt::Argon2') <&argon2-hash &argon2-verify>) !=== Nil {
        &hash-password = sub ( Str $password --> Str ) {
            argon2-hash($password).subst(/\0+$/,'');
        };
        &check-password = &argon2-verify
    }
    elsif (try require ::('Crypt::SodiumScrypt') <&scrypt-hash &scrypt-verify>) !=== Nil {
        &hash-password = &scrypt-hash;
        &check-password = &scrypt-verify
    }
    elsif (try require ::('Crypt::Bcrypt') <&bcrypt-hash &bcrypt-match>) !=== Nil {
        &hash-password = &bcrypt-hash;
        &check-password = sub ( Str $hash, Str $password --> Bool ) {
            bcrypt-match($password, $hash);
        };
    }
    elsif (try require ::('Crypt::Libcrypt') <&crypt &crypt-generate-salt>) !=== Nil {
        sub generate-salt(--> Str) {
            if crypt-generate-salt() -> $salt {
                $salt;
            }
            else {
                my @chars = (|("a" .. "z"), |("A" .. "Z"), |(0 .. 9));
                if $*DISTRO.name eq 'macosx' {
                    @chars.pick(2).join;
                }
                else {
                    '$6$' ~ @chars.pick(16).join ~ '$';
                }
            }
        }

        &hash-password = sub ( Str $password --> Str ) {
            crypt($password, generate-salt());
        };

        &check-password = sub ( Str $hash, Str $password --> Bool ) {
            crypt($password, $hash) eq $hash
        };
    }
    else {
       die q:to/EOMESS/;
        No hashing module installed, please install one of 'Crypt::SodiumPasswordHash', 'Crypt::Argon2', 'Crypt::SodiumScrypt' or 'Crypt::Libcrypt'
       EOMESS
    }

    %(
        '&hash-password'    =>  &hash-password,
        '&check-password'   =>  &check-password
    );
}

# vim: expandtab shiftwidth=4 ft=perl6
