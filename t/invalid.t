#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Crypt::Juniper;

my $warn = 0;

my @invalid = (undef, qw[ $9jadsfdf $9$asd $9$asdf* ]);
my $expected = @invalid;
plan tests => 1 + $expected;

#TODO: check warnings with Test::Warn

{
    $SIG{__WARN__} = sub { $warn++; print @_ };

    for my $crypt (@invalid)
    {
        # avoid undef interpolation without disabling warnings
        my $print = defined $crypt ? "'$crypt'" : 'undef';
        is(juniper_decrypt($crypt), undef,
           "Invalid crypt $print should return undef");
    }
}

is($warn, scalar @invalid, "$warn warns thrown, $expected expected");


