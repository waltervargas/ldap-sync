#!perl 

use strict;
use warnings;
use Test::Simple tests => 2; 

use Covetel::LDAP::Sync; 

my $ldap_src = Covetel::LDAP::AD->new({config => 't/root/ad.ini'});

my $usn;

my $sync = Covetel::LDAP::Sync->new({
            ldap_src    => $ldap_src,
            config      => 't/root/sync.ini',
            db          => 't/root/sync.db',
            log         => 't/root/sync.log',
});

ok($sync->full_sync(),"setting full sync");

$usn = $sync->{db}->get('highestCommittedUSN');

ok($usn ~~ 0,"value of highestCommittedUSN is 0");
