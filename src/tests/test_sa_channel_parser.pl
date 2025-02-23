#!/usr/bin/perl

use strict;
use warnings;
use Test::More;

use PMG::Utils;

my $kam_key = qq{-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF96bE0BEADsT1xRD2l19kmUSg9XMfRUtJbMGa9YAQ0a2fayT9IdmR38J4o3
Ln2fIR0CMa81Q+mi7pSdTpHGqR3t5GjmDGcCN8kwoHbmm0t5F9gK0tFAXThf+e40
kMdzLNzled4+5D83VyKCNaPm1tmogzYKKIEzTHCqQ7TdahWZDRDFiZJWFkd/9miE
kURY2uWLCttF+4Aa2AOHUg/7q00NSR8S0jWpLzpVNjbgi/jjkCafhpSZ56aqXHk3
QrTwJj3sznrLb9TkVZoXFKbBCh15m7mf5VVJVEZpj3BsvbcZJPnBFkCrzPjfShRz
lttRyiCFflOIcDrClg62tA/a1BmdUuIB5ktdCX8gB0F4t+9MhqgF89vT/OQpxywv
/QmuvKZzl77TQcLFHDlS+TKjLI6RdM3xuto1B8aSIYpKslnVpYuMpxNsvouAiQig
5qKBzYMbFCVge8Kjvcs6znxsPyjkCWgZVbf7ev7v+h71kkVfJ2TRR52ty/vsh82c
LYEaIB8CKYTstf69EOEQEhqMVNfhzuEb22ueYtAQSsnpLgGii0PwAFfSB4puzEUI
ItJVmD4DviD7ZfZnT8dR2bsysV4BF8s2dKX0KDnBAkzhlc30/iwt8j8bZXx3Evau
Ci+sFvBRMbpJJbVH8AJT7/dImn1ZqbK7jaZkFMticGBBWaKee8NYmF+KKwARAQAB
tDdLZXZpbiBBLiBNY0dyYWlsIChLQU0gQ2hhbm5lbCkgPGthbWNoYW5uZWxAbWNn
cmFpbC5jb20+iQJOBBMBCAA4FiEEIdlxQicskGb8qnkrShVtpSTAY9gFAl96bE0C
GwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQShVtpSTAY9hQZRAA5i8RkBCH
zjY/xHAoIUa4u9Di52I8t8IKHuIbH5a1TfShT8uj38ucmc/gRWMoOu1Tef9G2DdJ
FQc7KOA9GcGyGl1C2gfoTJEqBSNJTgJVfmHQ1Ef0ucNSjYFD3H0eFGTIuoSFy3Mi
g7CzxfhIJXIn4JW9sNwICH/7pOLke5Ihd5WvyOqU13FrfGemRbilviG73HYoy+Fh
4R9A1MLF3I0zVG5nszfn5CjSVG3c+Buj7Gk1d67noINbhCs2IPnyuOSvfrZc5wx1
ImCS8BpmGjXqaXZAIWLIhpMXvRiboGxX1zzRZLoz7Y5Y5h1MfnY2ASDMddmJpgOv
Vey/acAB4+6TtCgXmA6Wy8xmsqlId4qBocxX/jCMJ8OsuueYE6eF2jzS/JfbTndA
7pHOnCoR+ndMra5vaX8MYyGKqxxWyBoKWGgeBs8fSMwHAqRIo9GHWK67nBX0x39U
x9G0yn/A2dhaGqhui8xrcAHg/OGJErOlDw7YBeVX0RiS6awPyk9fo0IsGN0po2VX
bd9H8DKz1CXBLNZRG0vn5mViSOBzZeGU+K9aAs58GZ46LKA3YfWJ4s5W8BS+J3Ia
TFpq8U+OO/BSmOkMHZ+OPKWSlxNitFTyQsIdtS1PfqqYc+MK312LdmvrG2KWXE3N
EnuBffLm6uSOHJA6/0r6THJkffDSuvqM5yU=
=GVCC
-----END PGP PUBLIC KEY BLOCK-----};

my $tests = [
    [
	'./KAM_channel.conf', # input filename
	{                   # result structure
	    filename => './KAM_channel.conf',
	    channelurl => 'kam.sa-channels.mcgrail.com',
	    keyid => '24C063D8',
	    gpgkey => $kam_key,
	},
	undef,              # error string
    ],
    [
	'./missing_gpg_key_channel.conf',
	undef,
	'no GPG public key in ./missing_gpg_key_channel.conf!',
    ],
    [
	'./missing_keyid.conf',
	undef,
	'no KEYID in ./missing_keyid.conf!',
    ],
];

foreach my $test (@$tests) {
    my ($filename, $expect, $error) = @$test;

    my $result = eval { PMG::Utils::read_sa_channel($filename); };
    my $err = $@;

    if ($error) {
	like($err, qr/^\Q$error\E/, "expected error for $filename: $error");
    } else {
	is_deeply($result, $expect, "channel file: $filename parsed correctly");
    }
}

done_testing();
