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
which encrypt password and check a provided password against an encrypted hash.

The implementation for the C<hash-password> is provided by the first of:

=item L<Crypt::SodiumPasswordHash|https://github.com/jonathanstowe/Crypt-SodiumPasswordHash>

=item L<Crypt::Argon2|https://github.com/skinkade/p6-crypt-argon2>

=item L<Crypt::LibScrypt|https://github.com/jonathanstowe/Crypt-LibScrypt>

=item L<Crypt::SodiumScrypt|https://github.com/jonathanstowe/Crypt-SodiumScrypt>

=item L<Crypt::Libcrypt|https://github.com/jonathanstowe/Crypt-Libcrypt>

which can be found.  C<Crypt::Libcrypt> will be installed as a dependency so it
will nearly always work but is dependent on the mechanisms provided by the C<libcrypt>:
with a fairly recent C<libcrypt> it will be able to determine and use the best
available algorithm, falling back to attempt SHA-512, however if that isn't available
it may fall back to DES which is not considered secure enough for production use. You
can tell you are getting DES when the hash returned by C<hash-password> is only 13
characters long, if this is the case then you should install one of the other providers.

The C<check-password> will attempt to validate against all the available mechanisms
until one validates the password or the mechanisms are exhausted.  This is so that, if
you are validating against stored hashes, if a new supported module is installed or
this module is upgraded then you will still be able to verify against hashes made by a
previous mechanism.

=end pod


module Crypt::AnyPasswordHash {
}

sub EXPORT() {
    my &hash-password;
    my @checkers;

    my $DEBUG = ?%*ENV<CAPH_DEBUG> // False;

    my sub debug-load(Str $message) {
        note $message if $DEBUG;

    }

    {
        CATCH {
            default {
                debug-load("Couldn't load 'Crypt::SodiumPasswordHash'");
            }
        }
        if (require ::('Crypt::SodiumPasswordHash') <&sodium-hash &sodium-verify>) !=== Nil {
            if !&hash-password.defined {
                debug-load("Selected 'Crypt::SodiumPasswordHash'");
                &hash-password = &sodium-hash;
            }
            @checkers.append: &sodium-verify;
        }
    }
    {
        CATCH {
            default {
                debug-load("Couldn't load 'Crypt::Argon2'");
            }
        }
        if (require ::('Crypt::Argon2') <&argon2-hash &argon2-verify>) !=== Nil {
            if !&hash-password.defined {
                debug-load("Selected load 'Crypt::Argon2'");
                &hash-password = sub ( Str $password --> Str ) {
                    argon2-hash($password).subst(/\0+$/,'');
                };
            }
            @checkers.append: &argon2-verify;
        }
    }
    {
        CATCH {
            default {
                debug-load("Couldn't load 'Crypt::LibScrypt'");
            }
        }
        if ( require ::('Crypt::LibScrypt') <&scrypt-hash &scrypt-verify>) !=== Nil {
            if !&hash-password.defined {
                debug-load("Selected load 'Crypt::LibScrypt'");
                &hash-password = &scrypt-hash;
            }
            @checkers.append: &scrypt-verify;
        }
    }
    {
        CATCH {
            default {
                debug-load("Couldn't load 'Crypt::SodiumScrypt'");
            }
        }
        if ( require ::('Crypt::SodiumScrypt') <&scrypt-hash &scrypt-verify>) !=== Nil {
            if !&hash-password.defined {
                debug-load("Selected load 'Crypt::SodiumScrypt'");
                &hash-password = &scrypt-hash;
            }
            @checkers.append: &scrypt-verify;
        }
    }
    {
        CATCH {
            default {
                debug-load("Couldn't load 'Crypt::Bcrypt'");
            }
        }
        if ( require ::('Crypt::Bcrypt') <&bcrypt-hash &bcrypt-match>) !=== Nil {
            if !&hash-password.defined {
                debug-load("Selected load 'Crypt::Bcrypt'");
                &hash-password = &bcrypt-hash;
            }
            @checkers.append: sub ( Str $hash, Str $password --> Bool ) {
                bcrypt-match($password, $hash);
            };
        }
    }
    {
        CATCH {
            default {
                debug-load("Couldn't load 'Crypt::LibCrypt'");
            }
        }
        # Without the 'try' here it ends up by attempting to serialize a VMException under
        # some circumstances that appears to be related to when consumer is compiled
        if ( try require ::('Crypt::Libcrypt') <&crypt &crypt-generate-salt>) !=== Nil {
            if !&hash-password.defined {
                debug-load("Selected load 'Crypt::LibCrypt'");
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
            }

            @checkers.append: sub ( Str $hash, Str $password --> Bool ) {
                (crypt($password, $hash) // '' )  eq $hash
            };
        }
    }
    if !&hash-password.defined {
       die q:to/EOMESS/;
        No hashing module installed, please install one of 'Crypt::SodiumPasswordHash', 'Crypt::Argon2', 'Crypt::SodiumScrypt' or 'Crypt::Libcrypt'
       EOMESS
    }

    my &check-password = sub ( Str $hash, Str $password --> Bool ) {
        my $rc = False;
        for @checkers -> &check {
            if check($hash, $password ) {
                $rc = True;
                last;
            }
        }
        $rc;
    };

    %(
        '&hash-password'    =>  &hash-password,
        '&check-password'   =>  &check-password
    );
}

# vim: expandtab shiftwidth=4 ft=raku
