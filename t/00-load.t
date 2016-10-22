#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Covetel::LDAP::Sync' ) || print "Bail out!\n";
}

diag( "Testing Covetel::LDAP::Sync $Covetel::LDAP::Sync::VERSION, Perl $], $^X" );
