#!/usr/bin/env perl6

use v6;

use Test;

use Crypt::AnyPasswordHash;

my @chars = (|("a" .. "z"), |("A" .. "Z"), |(0 .. 9));

my $password = @chars.pick(20).join;
my $hash;
lives-ok { $hash = hash-password($password) }, 'hash-password';
diag "got hash : '$hash'";
lives-ok { ok check-password($hash, $password), "verify ok" }, 'check-password';
lives-ok { nok check-password($hash, $password.comb.reverse.join), "verify nok with wrong password" }, 'check-password';


done-testing;
# vim: expandtab shiftwidth=4 ft=perl6
