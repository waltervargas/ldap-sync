use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Covetel::LDAP::Sync',
    AUTHOR              => q{Walter Vargas <walter@covetel.com.ve>},
    VERSION_FROM        => 'lib/Covetel/LDAP/Sync.pm',
    ABSTRACT_FROM       => 'lib/Covetel/LDAP/Sync.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
		'Config::Any::Base'         => '0',
		'Config::Tiny'              => '0',
		'Convert::ASN1::IO'         => '0',
		'Convert::ASN1::_decode'    => '0',
		'Convert::ASN1::_encode'    => '0',
		'Convert::ASN1::parser'     => '0',
		'Convert::ASN1::Debug'      => '0',
		'Unicode::Map8'             => '0',
		'Unicode::String'           => '0',
		'Digest::SHA1'              => '0',
		'Net::LDAPS'                => '0',
		'Covetel::LDAP::AD'         => '0',
		'Covetel::LDAP::OpenLDAP'   => '0',
		'Log::Dispatch::File'       => '0',
		'Net::LDAP::Control::Paged' => '0',
		'Config::Any::INI'          => '0',
		'Covetel::LDAP'             => '0',
		'common::sense'             => '0',
		'Net::LDAP::Entry'          => '0',
		'DBM::Deep'                 => '0',
		'Log::Dispatch'             => '0',
		'Net::LDAP::Constant'       => '0',
		'DBM::Deep::Array'          => '0',
		'DBM::Deep::Engine'         => '0',
		'DBM::Deep::Hash'           => '0',
		'DBM::Deep::Iterator'       => '0',
		'Socket6'                   => '0',
		'Net::LibIDN'               => '0',
		'Net::SSLeay'               => '0',
		'Log::Dispatch::Base'       => '0',
		'Log::Dispatch::Output'     => '0',
		'Params::Validate'          => '0',
		'IO::Socket::SSL'           => '0',
		'Net::LDAP::Bind'           => '0',
		'Net::LDAP::Extension'      => '0',
		'Net::LDAP::RootDSE'        => '0',
		'Net::LDAP::Schema'         => '0',
		'Net::LDAP::Search'         => '0',
		'IO::Socket::INET6'         => '0',
		'Net::LDAP::Filter'         => '0',
		'Convert::ASN1'             => '0',
		'Net::LDAP::ASN'            => '0',
		'Net::LDAP::Control'        => '0',
		'Net::LDAP::Message'        => '0',
		'Net::LDAP::LDIF'           => '0',
		'Net::LDAP::Util'           => '0',
		'Net::LDAP::Intermediate'   => '0',
		'Net::LDAP'                 => '0',
		'Params::ValidatePP'        => '0',
		'Params::ValidateXS'        => '0',
		'Unicode::CharName'         => '0',
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Covetel-LDAP-Sync-*' },
);
