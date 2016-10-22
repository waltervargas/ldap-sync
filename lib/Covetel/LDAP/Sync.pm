package Covetel::LDAP::Sync;
use common::sense;
use Covetel::LDAP;
use Covetel::LDAP::OpenLDAP;
use Covetel::LDAP::AD;
use DBM::Deep;
use Log::Dispatch;
use Log::Dispatch::File;
use Net::LDAP::Control::Paged;
use Net::LDAP::Constant qw( LDAP_CONTROL_PAGED );
use Data::Dumper;
use Digest::MD5 qw(md5_base64);

=head1 NAME

Covetel::LDAP::Sync - Sync ActiveDirectory to OpenLDAP

=head1 VERSION

Version 0.05

=cut

our $VERSION = '0.06';

=head1 SYNOPSIS

    my $ldap_src = Covetel::LDAP::AD->new({config => 'ad.ini'});
    my $ldap_dst = Covetel::LDAP::OpenLDAP->new({config => 'openldap.ini'});

    my $sync = Covetel::LDAP::Sync->new({
            ldap_src    => $ldap_src,
            ldap_dst    => $ldap_dst,
            config      => 'sync.ini',
            db          => 'sync.db',
            log         => 'sync.log',
    });


    $sync->run("user");
    $sync->run("group");
    $sync->run("list");


=head1 SUBROUTINES/METHODS

=head2 new

The constructor: 

    my $sync = Covetel::LDAP::Sync->new({
            ldap_src    => $ldap_src,
            ldap_dst    => $ldap_dst,
            config      => 'sync.ini',
            db          => 'sync.db',
            log         => 'sync.log',
    });

=cut

sub new {
    my $class   = shift;
    my $options = shift;
    my $self    = {};

    $self->{config_file} = $options->{config};
    $self->{db_file}     = $options->{db};
    $self->{dst}         = $options->{ldap_dst};
    $self->{src}         = $options->{ldap_src};
    $self->{log_file}    = $options->{log};
    $self->{log_level}   = $options->{log_level};
    bless $self, $class;

    $self->initialize();
    return $self;
}

=head2 full_sync

 $sync->full_sync(); # enable full sync

=cut

sub full_sync {
    my $self = shift;

    # Save old highestCommittedUSN
    my $usn = $self->{db}->get('highestCommittedUSN');
    $self->{db}->put( "oldUSN", $usn );

    # Set highestCommittedUSN to 0
    $self->{db}->put( "highestCommittedUSN", 0 );

    # Save full_sync flag
    $self->{full_sync} = 1;
}

=head2 _src_is_ad 

Return true if ldap_src is an instance of Covetel::LDAP::AD

=cut

sub _src_is_ad {
    my $self = shift;

    my $ldap = ref $self->{src};

    if ( $ldap eq 'Covetel::LDAP::AD' ) {
        return 1;
    }
    else {
        return 0;
    }

}

=head2 initialize

Initialize configuration

=cut

sub initialize {
    my $self      = shift;
    my $log_level = shift;
    $self->_load_db if $self->_src_is_ad;
    $self->_load_config;
    $self->_load_log();

}

=head2 _load_db

Load DBM::DB persistence database. 

=cut

sub _load_db {
    my $self = shift;

    my $db = DBM::Deep->new(
        file      => $self->{'db_file'},
        locking   => 1,
        autoflush => 0,
        pack_size => 'small',
    );
    if ( $self->{'full_sync'} ) {
        $db->put( "highestCommittedUSN", 0 );
    }

    $self->{db} = $db;
}

=head2 _load_config

Load configuration file

=cut

sub _load_config {
    my $self = shift;
    if ( -e $self->{'config_file'} ) {
        my $config = Config::Any::INI->load( $self->{'config_file'} );
        $self->{'config'} = $config;
    }
    else {
        die "Config File " . $self->{'config_file'} . " does not exist";
    }
}

=head2 _load_log

Load Logs

=cut

sub _load_log {
    my $self  = shift;
    my $level = $self->{log_level} || 'error';
    my $log   = Log::Dispatch->new;

    $log->add(
        Log::Dispatch::File->new(
            name      => 'sync.log',
            min_level => $level,
            filename  => $self->{log_file},
            mode      => '>>',
            newline   => 1,
        ),
    );

    $self->{log} = $log;
}

=head2 log

return Log::Dispatch object

=cut

sub log {
    my $self = shift;

    return $self->{log};
}

=head2 logger

set log with time

=cut

sub logger {
    my $self    = shift;
    my $options = shift;

    my $timestamp = localtime;

    $self->log->log(
        level   => $options->{'level'},
        message => localtime . ' - ' . $options->{'message'} . "\n",
    );
}

=head2 config

return configuration

=cut

sub config {
    my ($self) = @_;
    return $self->{config};
}

=head2 filter 

Set/Get filter.

=cut

sub filter {
    my ( $self, $filter ) = @_;
    if ($filter) {
        $self->{filter}      = $filter;
        $self->{user_filter} = 1;
    }
    else {
        return $self->{filter};
    }
}

=head2 run

Intialize synchronization

=cut

sub run {
    my $self    = shift;
    my $target  = shift;
    my $perpage = shift;

    #if $perpage !== 0 return 1000(default) else return $perpage
    $perpage =
      ( ( !( $perpage ~~ 0 ) && $perpage == 0 ) ? 1000 : $perpage )
      ;    #default AD pagination size

    $self->{status} = {
        'upd_entries'       => 0,
        'new_entries'       => 0,
        'errors'            => 0,
        'blacklist_entries' => 0
    };
    if ( $self->_src_is_ad ) {
        $self->fetch_high_usn();
    }

    # Prepare search filter
    $self->_prepare_filter($target) unless $self->{user_filter};

    if ( $self->{dst}->bind && $self->{src}->bind ) {
    if ($self->{dst}->get_maintenance_gidNumber) {

        my $args;
        my $page;
        if ( $perpage > 0 ) {

            # Set Page Length
            $page = Net::LDAP::Control::Paged->new( size => $perpage );

            # Prepare Search Arguments
            given ($target) {
                when ('user')  { 
                    $args = {
                        base    => $self->{src}->base_people,
                        scope   => "sub",
                        filter  => $self->filter,
                        control => $page
                    };
                }
                when ('group') {
                    $args = {
                        base    => $self->{src}->base_group,
                        scope   => "sub",
                        filter  => $self->filter,
                        control => $page
                    };
                }
                when ('list') {
                    $args = {
                        base    => $self->{src}->base_list,
                        scope   => "sub",
                        filter  => $self->filter,
                        control => $page
                    };
                }
            }
        }
        else {
            given ($target) {
                when ('user')  { 
                    $args = {
                        base    => $self->{src}->base_people,
                        scope   => "sub",
                        filter  => $self->filter,
                    };
                }
                when ('group') {
                    $args = {
                        base    => $self->{src}->base_group,
                        scope   => "sub",
                        filter  => $self->filter,
                    };
                }
                when ('list') {
                    $args = {
                        base    => $self->{src}->base_list,
                        scope   => "sub",
                        filter  => $self->filter,
                    };
                }
            }
        }

        my $cookie;

        $self->logger(
            {
                level   => 'info',
                message => 'Filter ' . $self->{filter} . " \n"
            }
        );

        my $result =
            $perpage > 0
          ? $self->{src}->paged_search($args)
          : $self->{src}->search($args);
        $self->handle_result( $result, $target );

        }else{
            $self->logger(
                {
                    level   => 'info',
                    message => "A ocurrido un Error\nPor favor verifique que exista la rama mantenimiento y el usuario mantenimiento\n"
                }
            );
            say "A ocurrido un Error\nPor favor verifique que exista la rama mantenimiento y el usuario mantenimiento\n"
        }
    }
    else {
        if ( $self->{src}->{mesg}->is_error ) {
            my $mesg = $self->{src}->{mesg};
            die $mesg->error . "\n"
              . $mesg->code . "\n"
              . $mesg->error_name . "\n"
              . $mesg->error_text . "\n"
              . $mesg->error_desc;
        }
        elsif ( $self->{src}->{mesg}->is_error ) {
            my $mesg = $self->{src}->{mesg};
            die $mesg->error . "\n"
              . $mesg->code . "\n"
              . $mesg->error_name . "\n"
              . $mesg->error_text . "\n"
              . $mesg->error_desc;
        }
        else {
            say "Something horrible is happening !";
        }

    }
    $self->{user_filter} = 0;
    if ( $self->_src_is_ad ) {
        my $new_usn = $self->get_high_usn;
        return $new_usn;
    }

}

=head2 handle_result

Handles the LDAP Search result for each entry found

=cut

sub handle_result {
    my $self   = shift;
    my $result = shift;
    my $target = shift;

    if ( $result->is_error ) {

        # save errors in $error
        my $error =
            $result->error . "\n"
          . $result->code . "\n"
          . $result->error_name . "\n"
          . $result->error_text . "\n"
          . $result->error_desc;

        # save $error in sync.log
        $self->logger(
            {
                level   => 'error',
                message => $error
            }
        );
        $self->{result} = $result;
        return 0;
    }
    my $it = 0;
    if ( $result->count > 0 ) {
        $self->logger(
            {
                level   => 'alert',
                message => 'Processing ' . $result->count . " entries.\n"
            }
        );

        for my $entry ( $result->entries ) {
            if ( $self->_black_list($entry) ) {
                $self->{status}->{'blacklist_entries'}++;
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Blacklisted entry: ' . $entry->dn
                    }
                );
                next;
            }
            my $entry = $self->_prepare_entry( $entry, $target );

            next if ( $self->{dry_run} || !$entry );

            my $mesg = $entry->update( $self->{dst}->{ldap} );
            if ( $mesg->is_error ) {

                # save errors in $error
                my $error =
                    "An error occurred while trying to sync entry: "
                  . $entry->dn . "\n"
                  . $mesg->error . "\n"
                  . $mesg->code . "\n"
                  . $mesg->error_name . "\n"
                  . $mesg->error_text . "\n"
                  . $mesg->error_desc;

                # save $error in sync.log
                $self->logger(
                    {
                        level   => 'error',
                        message => $error
                    }
                );
                $self->{status}->{'errors'}++;
            }
            else {
                $self->logger(
                    {
                        level   => 'info',
                        message => 'Sync: ' . $entry->dn
                    }
                );
            }
        }
        $self->logger(
            {
                level   => 'alert',
                message => "Sync for $target Complete\n"
                  . "new entries: "
                  . $self->{status}->{'new_entries'} . "\n"
                  . "updated entries: "
                  . $self->{status}->{'upd_entries'} . "\n"
                  . "blacklisted entries: "
                  . $self->{status}->{'blacklist_entries'} . "\n"
                  . "errors: "
                  . $self->{status}->{'errors'} . "\n"
            }
        );

    }
    else {

        # no entries found
        $self->logger(
            {
                level   => 'info',
                message => 'The Search doesnt return any entries ! :( '
            }
        );
        return 0;
    }
    return 1;
}

=head2 _prepare_filter

Return filter for search in src ldap.

=cut

sub _prepare_filter {
    my $self = shift;
    my $type = shift;

    given ($type) {
        when ('user')  { return $self->_filter_user_src; }
        when ('group') { return $self->_filter_group_src; }
        when ('list') { return $self->_filter_list_src; }
    }

}

=head2 _filter_user_src

Return filter for search users in src ldap.

=cut

sub _filter_user_src {
    my $self = shift;
    my $filter;

    if ( $self->_src_is_ad ) {
        my $usn = $self->{usn};
        $filter =
            '(&(objectClass=person)'
          . "(uSNChanged>=$usn)"
          . "(&(!(sAMAccountType=536870912)))"
          . "(!(isCriticalSystemObject=TRUE))" 
          . "(!(objectClass=computer))". ')';

    }
    else {
        $filter = '(objectClass=person)';
    }
    $self->filter($filter);
}

=head2 _filter_group_src

Return filter for search groups in src ldap.

=cut

sub _filter_group_src {
    my $self = shift;
    my $filter;

    if ( $self->_src_is_ad ) {
        my $usn = $self->{usn};
        $filter =
            '(&(objectClass=group)'
          . "(uSNChanged>=$usn)"
          . "(&(!(sAMAccountType=536870912)))"
          . "(!(isCriticalSystemObject=TRUE))" . ')';
    }
    else {
        $filter = '(objectClass=groupOfNames)';
    }
    $self->filter($filter);
}

=head2 _filter_list_src

Return filter for search list in src ldap.

=cut

sub _filter_list_src {
    my $self = shift;
    my $filter;

    if ( $self->_src_is_ad ) {
        my $usn = $self->{usn};
        $filter =
            '(&(objectClass=group)'
          . "(uSNChanged>=$usn)"
          . "(&(!(sAMAccountType=536870912)))"
          . "(!(isCriticalSystemObject=TRUE))" . ')';
    }
    else {
        $filter = '(objectClass=groupOfNames)';
    }
    $self->filter($filter);
}

=head2 _prepare_entry

=cut

sub _prepare_entry {
    my ( $self, $src_entry, $type ) = @_;

    given ($type) {
        when ('user') {
            given ($self->{config}->{personObjectClass}->{objectClass}) {
                when ($_ =~ /posixAccount/ && $self->{config}->{info}->{cliente} eq '') {
                    return $self->_prepare_entry_user_posixAccount($src_entry);
                }
                when ($_ =~ /posixAccount/ && $self->{config}->{info}->{cliente} eq 'EXAMPLE') {
                    return $self->_prepare_entry_user_posixAccount_EXAMPLE($src_entry);
                }
                default {
                    return $self->_prepare_entry_user($src_entry);
                }
            }
        }
        when ('group') {  
            given ($self->{config}->{groupObjectClass}->{"objectClass"}) {
                when ($_ =~ /posixGroup/ && $self->{config}->{info}->{cliente} eq '') {
                    return $self->_prepare_entry_group_posixgroup($src_entry);
                } 
                when ($_ =~ /posixGroup/ && $self->{config}->{info}->{cliente} eq 'EXAMPLE') {
                    return $self->_prepare_entry_group_posixgroup_EXAMPLE($src_entry);
                }
                default {
                    return $self->_prepare_entry_group($src_entry);
                } 
            }
        }
        when ('list') {return $self->_prepare_entry_list_sendmailMTA($src_entry); }
    }
}

=head2 _prepare_entry_user

Prepare user entry to sync

=cut

sub _prepare_entry_user {
    my ( $self, $src_entry ) = @_;

    # Read the filter field for Active Directory.
    my $f_f_ad = $self->{config}->{general}->{filter};

    # Read the filter map for OpenLDAP.
    my $f_f_ol = $self->{config}->{person_map}->{$f_f_ad};

    my $value  = $src_entry->get_value($f_f_ad);
    my $filter = "($f_f_ol=$value)";

    my $result = $self->{dst}->search(
        {
            base   => $self->{dst}->{config}->{base},
            scope  => "sub",
            filter => $filter
        }
    );

    my $dest_entry =
        $result->count > 0
      ? $result->shift_entry
      : Net::LDAP::Entry->new;

    # prepare dn if empty
    unless ( $dest_entry->dn ) {
        my $field = $self->{config}->{general}->{rdn_user_field_dst};
        my $field_dst = $self->{config}->{person_map}->{$field};

        # Buscar el valor correspondiente a $field en la fuente.
        my $valor = $src_entry->get_value($field);
        $valor =~ s/,//g;
        my $dn    = $field_dst . '=' . $valor . ',' . $self->{dst}->base_people;
        $dest_entry->dn($dn);
    }

    # prepare attrs if attr list is empty
    unless ( $dest_entry->attributes ) {
        $self->logger(
            {
                level   => 'info',
                message => 'New entry: ' . $dest_entry->dn,
            }
        );
        $self->{status}->{'new_entries'}++;

        my $objectClass = $self->{config}->{personObjectClass}->{"objectClass"};
        my @oc = split( / /, $objectClass );

        $dest_entry->add( objectClass => [@oc] );

        foreach ( keys %{ $self->{config}->{person_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            if ( $value_src ne '' ) {
                $dest_entry->add( $self->{config}->{person_map}->{$_} =>
                      $src_entry->get_value($_), );
            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: ['
                          . $_
                          . '] Doesnt exist or is empty'
                    }
                );
            }
        }
    }
    else {    #update
        $self->logger(
            {
                level   => 'info',
                message => 'Updating entry: ' . $dest_entry->dn,
            }
        );
        $self->{status}->{'upd_entries'}++;
        foreach ( keys %{ $self->{config}->{person_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            my $value_dst =
              $dest_entry->get_value( $self->{config}->{person_map}->{$_},
                asref => 1 );

            if ($value_src) {
                if ($value_dst) {
                    $dest_entry->replace( $self->{config}->{person_map}->{$_} =>
                          $src_entry->get_value($_), );
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: ['
                              . $self->{config}->{person_map}->{$_}
                              . '] replaced'
                        }
                    );
                }
                else {
                    $dest_entry->add( $self->{config}->{person_map}->{$_} =>
                          $src_entry->get_value($_), );
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: ['
                              . $self->{config}->{person_map}->{$_}
                              . '] aggregated'
                        }
                    );
                }
            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: ['
                          . $_
                          . '] Doesnt exists or is empty'
                    }
                );
            }

        }
    }

    return $dest_entry;

}

=head2 _prepare_entry_gorup

Prepare group entry to sync

=cut

sub _prepare_entry_group {
    my ( $self, $src_entry ) = @_;

    # Attribute with which to build the group dn

    my $at_dn = $self->{config}->{general}->{"rdn_dn_group_dst"}; 

    # Read the filter field for Active Directory.

    my $value  = $src_entry->get_value($at_dn);
    my $filter = "($at_dn=$value)";

    my $result = $self->{dst}->search(
        {
            base   => $self->{dst}->{config}->{base},
            scope  => "sub",
            filter => $filter
        }
    );

    my $dest_entry =
        $result->count > 0
      ? $result->shift_entry
      : Net::LDAP::Entry->new;

    # prepare dn if empty
    unless ( $dest_entry->dn ) {
        my $field = $at_dn;
        my $dn    = $field . '=' . $value . ',' . $self->{dst}->base_group;
        $dest_entry->dn($dn);
    }

    my $has_members = 0;

    # prepare attrs if attr list is empty
    unless ( $dest_entry->attributes ) {
        $self->logger(
            {
                level   => 'info',
                message => 'New entry: ' . $dest_entry->dn,
            }
        );

        my $objectClass = $self->{config}->{groupObjectClass}->{"objectClass"};
        my @oc = split( / /, $objectClass );
        $dest_entry->add( objectClass => [@oc] );
        foreach ( keys %{ $self->{config}->{group_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            if ( $value_src ne '' ) {
                my $attr = $self->{config}->{group_map}->{$_};
                my $val =
                  $src_entry->get_value( $_, alloptions => 1, asref => 1 );
                $val = $val->{''};
                if ( $attr eq 'member' ) {
                    $val         = $self->_get_member_value($val);
                    $has_members = ( $val != 0 );
                }
                $dest_entry->add( $attr => $val );

            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: ['
                          . $_
                          . '] Doesnt exist or is empty'
                    }
                );
            }
        }
        if ($has_members) {
            $self->{status}->{'new_entries'}++;
        }
        else {
            $self->{status}->{'errors'}++;
            $self->logger(
                {
                    level   => 'error',
                    message => 'Group entry '
                      . $dest_entry->dn
                      . ' must have at least one member.'
                }
            );
            $dest_entry = 0;

        }

    }
    else {    #update
        $self->logger(
            {
                level   => 'info',
                message => 'Updating entry: ' . $dest_entry->dn,
            }
        );

        foreach ( keys %{ $self->{config}->{group_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            my $value_dst =
              $dest_entry->get_value( $self->{config}->{group_map}->{$_},
                asref => 1 );
            my $attr = $self->{config}->{group_map}->{$_};
            my $val = $src_entry->get_value( $_, alloptions => 1, asref => 1 );
            $val = $val->{''};
            if ( $attr eq 'member' ) {
                $val         = $self->_get_member_value($val);
                $has_members = ( $val != 0 );
            }
            if ($value_src) {
                if ($value_dst) {
                    $dest_entry->replace( $attr => $val );
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: [' . $attr . '] replaced'
                        }
                    );
                }
                else {
                    $dest_entry->add( $attr => $val );
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: [' . $attr . '] aggregated'
                        }
                    );
                }
            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: ['
                          . $_
                          . '] Doesnt exists or is empty'
                    }
                );
            }
        }
        if ($has_members) {
            $self->{status}->{'upd_entries'}++;
        }
        else {
            $self->{status}->{'errors'}++;
            $self->logger(
                {
                    level   => 'error',
                    message => 'Group entry '
                      . $dest_entry->dn
                      . ' must have at least one member.'
                }
            );
            $dest_entry = 0;

        }
    }

    return $dest_entry;

}

=head2 _prepare_entry_group_posixgroup

Prepare group entry to sync

=cut

sub _prepare_entry_group_posixgroup {
    my ( $self, $src_entry ) = @_;

    # Attribute with which to build the group dn

    my $at_dn = $self->{config}->{general}->{"rdn_dn_group_dst"}; 

    # Read the filter field for Active Directory.

    my $value  = $src_entry->get_value($at_dn);
    my $filter = "($at_dn=$value)";

    my $result = $self->{dst}->search(
        {
            base   => $self->{dst}->{config}->{base},
            scope  => "sub",
            filter => $filter
        }
    );

    my $dest_entry =
        $result->count > 0
      ? $result->shift_entry
      : Net::LDAP::Entry->new;

    # prepare dn if empty
    unless ( $dest_entry->dn ) {
        my $field = $at_dn;
        my $dn    = $field . '=' . $value . ',' . $self->{dst}->base_group;
        $dest_entry->dn($dn);
    }

    my $has_members = 0;

    # prepare attrs if attr list is empty
    unless ( $dest_entry->attributes ) {
        $self->logger(
            {
                level   => 'info',
                message => 'New entry: ' . $dest_entry->dn,
            }
        );

        my $objectClass = $self->{config}->{groupObjectClass}->{"objectClass"};
        my @oc = split( / /, $objectClass );
        $dest_entry->add( objectClass => [@oc] );
        foreach ( keys %{ $self->{config}->{group_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            if ( $value_src ne '' || $_ eq 'gidNumber' ) {
                my $attr = $self->{config}->{group_map}->{$_};
                my $val = $src_entry->get_value( $_, alloptions => 1, asref => 1 );
                $val = $val->{''};
                given ($attr) {
                    when ('memberUid') {
                        $val         = $self->_get_member_value_posixgroup($val);
                        $has_members = ( $val != 0 );
                    }
				    when ('gidNumber') { 
                        if ($self->{config}->{general}->{get_inc_uidN} == 1) {
                            $val = $self->{dst}->get_maintenance_gidNumber ?
                            $self->{dst}->get_maintenance_gidNumber :
                            $self->{dst}->get_people_gidNumber + int rand( 20000 - 10000 + 1 );
                        }else{
                            $val = $self->{dst}->get_people_gidNumber + $self->{status}->{'new_entries'}; 
                        }
                    }
                }
                $dest_entry->add( $attr => $val, 
                );
				$self->{dst}->increase_maintenance_gidNumber;
            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: [' 
                          . $_
                          . '] Doesnt exist or is empty'
                    }
                );
            }
        }
        if ($has_members) {
            $self->{status}->{'new_entries'}++;
        }
        else {
            $self->{status}->{'errors'}++;
            $self->logger(
                {
                    level   => 'error',
                    message => 'Group entry '
                      . $dest_entry->dn
                      . ' must have at least one member.'
                }
            );
            $dest_entry = 0;

        }

    }
    else {    #update
        $self->logger(
            {
                level   => 'info',
                message => 'Updating entry: ' . $dest_entry->dn,
            }
        );

        foreach ( keys %{ $self->{config}->{group_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            my $value_dst =
              $dest_entry->get_value( $self->{config}->{group_map}->{$_},
                asref => 1 );
            my $attr = $self->{config}->{group_map}->{$_};
            my $val = $src_entry->get_value( $_, alloptions => 1, asref => 1 );
            $val = $val->{''};
            given ($attr) {
                when ('memberUid') {
                    $val         = $self->_get_member_value_posixgroup($val);
                    $has_members = ( $val != 0 );
                }
            }
            if ($value_src) {
                if ($value_dst) {
                    $dest_entry->replace( $attr => $val, );
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: [' . $attr . '] replaced'
                        }
                    );
                }
                else {
                    $dest_entry->add( $attr => $val, 
                                      gidNumber => $self->{dst}->get_people_gidNumber ? $self->{dst}->get_people_gidNumber : 10000,
                                    );
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: [' . $attr . '] aggregated'
                        }
                    );
                }
            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: [' 
                          . $_
                          . '] Doesnt exists or is empty'
                    }
                );
            }
        }
        if ($has_members) {
            $self->{status}->{'upd_entries'}++;
        }
        else {
            $self->{status}->{'errors'}++;
            $self->logger(
                {
                    level   => 'error',
                    message => 'Group entry '
                      . $dest_entry->dn
                      . ' must have at least one member.'
                }
            );
            $dest_entry = 0;

        }
    }

    return $dest_entry;

}

=head2 _prepare_entry_group_posixgroup_EXAMPLE

Prepare group entry for sync with EXAMPLE requirement

=cut

sub _prepare_entry_group_posixgroup_EXAMPLE {
    my ( $self, $src_entry ) = @_;

    # Attribute with which to build the group dn

    my $at_dn = $self->{config}->{general}->{"rdn_dn_group_dst"}; 

    # Read the filter field for Active Directory.

    my $value  = $src_entry->get_value($at_dn);
    my $filter = "($at_dn=$value)";

    my $result = $self->{dst}->search(
        {
            base   => $self->{dst}->{config}->{base},
            scope  => "sub",
            filter => $filter
        }
    );

    my $dest_entry =
        $result->count > 0
      ? $result->shift_entry
      : Net::LDAP::Entry->new;

    # prepare dn if empty
    unless ( $dest_entry->dn ) {
        my $field = $at_dn;
        my $dn    = $field . '=' . $value . ',' . $self->{dst}->base_group;
        $dest_entry->dn($dn);
    }

    my $has_members = 0;

    # prepare attrs if attr list is empty
    unless ( $dest_entry->attributes ) {
        $self->logger(
            {
                level   => 'info',
                message => 'New entry: ' . $dest_entry->dn,
            }
        );

        my $objectClass = $self->{config}->{groupObjectClass}->{"objectClass"};
        my @oc = split( / /, $objectClass );
        $dest_entry->add( objectClass => [@oc] );
        foreach ( keys %{ $self->{config}->{group_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            if ( $value_src ne '' || $_ eq 'gidNumber' ) {
                my $attr = $self->{config}->{group_map}->{$_};
                my $val = $src_entry->get_value( $_, alloptions => 1, asref => 1 );
                $val = $val->{''};
                given ($attr) {
                    when ('memberUid') {
                        if ($self->{config}->{general}->{verify_group_members} == 1) {
                            $val = $self->_get_member_value_posixgroup($val);
                        }else{
                            $val = $self->_get_member_uid($val);
                        }
                        $has_members = ( $val != 0 );
                    }
				    when ('gidNumber') { 
                        my $sid = &ConvertSidToStringSid($src_entry->get_value('objectSid'));
                        $sid =~ /(\d*$)/;
                        $val = ($1 + 500000);
                    }
                }
                $dest_entry->add( $attr => $val, 
                );
				$self->{dst}->increase_maintenance_gidNumber;
            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: [' 
                          . $_
                          . '] Doesnt exist or is empty'
                    }
                );
            }
        }
        if ($has_members) {
            $self->{status}->{'new_entries'}++;
        }
        else {
            $self->{status}->{'errors'}++;
            $self->logger(
                {
                    level   => 'error',
                    message => 'Group entry '
                      . $dest_entry->dn
                      . ' must have at least one member.'
                }
            );
            $dest_entry = 0;

        }

    }
    else {    #update
        $self->logger(
            {
                level   => 'info',
                message => 'Updating entry: ' . $dest_entry->dn,
            }
        );

        foreach ( keys %{ $self->{config}->{group_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            my $value_dst =
              $dest_entry->get_value( $self->{config}->{group_map}->{$_},
                asref => 1 );
            my $attr = $self->{config}->{group_map}->{$_};
            my $val = $src_entry->get_value( $_, alloptions => 1, asref => 1 );
            $val = $val->{''};
            given ($attr) {
                when ('memberUid') {
                        if ($self->{config}->{general}->{verify_group_members} == 1) {
                            $val = $self->_get_member_value_posixgroup($val);
                        }else{
                            $val = $self->_get_member_uid($val);
                        }
                    $has_members = ( $val != 0 );
                }
            }
            if ($value_src) {
                if ($value_dst) {
                    $dest_entry->replace( $attr => $val, );
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: [' . $attr . '] replaced'
                        }
                    );
                }
                else {
                    $dest_entry->add( $attr => $val, 
                                      gidNumber => $self->{dst}->get_people_gidNumber ? $self->{dst}->get_people_gidNumber : 10000,
                                    );
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: [' . $attr . '] aggregated'
                        }
                    );
                }
            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: [' 
                          . $_
                          . '] Doesnt exists or is empty'
                    }
                );
            }
        }
        if ($has_members) {
            $self->{status}->{'upd_entries'}++;
        }
        else {
            $self->{status}->{'errors'}++;
            $self->logger(
                {
                    level   => 'error',
                    message => 'Group entry '
                      . $dest_entry->dn
                      . ' must have at least one member.'
                }
            );
            $dest_entry = 0;

        }
    }

    return $dest_entry;

}

=head2 _prepare_entry_list_sendmailMTA

Prepare list entry to sync

=cut

sub _prepare_entry_list_sendmailMTA {
    my ( $self, $src_entry ) = @_;

    # Attribute with which to build the group dn

    my $at_dn = $self->{config}->{general}->{"rdn_dn_list_dst"}; 

    # Read the filter field for Active Directory.

    my $value  = $src_entry->get_value($at_dn);
    my $filter = "($at_dn=$value)";

    my $result = $self->{dst}->search(
        {
            base   => $self->{dst}->{config}->{base},
            scope  => "sub",
            filter => $filter
        }
    );

    my $dest_entry =
        $result->count > 0
      ? $result->shift_entry
      : Net::LDAP::Entry->new;

    # prepare dn if empty
    unless ( $dest_entry->dn ) {
        my $field = $at_dn;
        if ($value eq '') {
            if ($src_entry->get_value('mailNickname') eq '') {
                $value = $src_entry->get_value('sAMAccountName').'@'.$self->{config}->{info}->{dominio};
            }else{
                $value = $src_entry->get_value('mailNickname').'@'.$self->{config}->{info}->{dominio};
            }
        }
        $value =~ tr/áéíóúüñçÁÉÍÓÚÜÑÇ/aeiouuncAEIOUUNC/; 
        
        my $dn    = $field . '=' . $value . ',' . $self->{dst}->base_list;
        $dest_entry->dn($dn);
    }

    my $has_members = 0;

    # prepare attrs if attr list is empty
    unless ( $dest_entry->attributes ) {
        $self->logger(
            {
                level   => 'info',
                message => 'New entry: ' . $dest_entry->dn,
            }
        );

        my $objectClass = $self->{config}->{listObjectClass}->{"objectClass"};
        my @oc = split( / /, $objectClass );
        $dest_entry->add( objectClass => [@oc] );
        foreach ( keys %{ $self->{config}->{list_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            if ( $value_src ne '' || $_ eq 'homeDirectory' || $_ eq 'mailhost' || $_ eq 'sendmailMTAAliasGrouping' || $_ eq 'sendmailMTAKey' ) {
                my $attr = $self->{config}->{list_map}->{$_};
                my $val = $src_entry->get_value( $_, alloptions => 1, asref => 1 );
                $val = $val->{''};
                given ($attr) {
                    when ('sAMAccountName') {
                        $attr = 'sendmailMTAKey';
                        $val = $src_entry->get_value($_);
                    }
                    when ('homeDirectory') { $val = $self->{config}->{values_for_lists}->{$attr}; }
                    when ('mailhost') { $val = $self->{config}->{values_for_lists}->{$attr}; }
                    when ('sendmailMTAAliasGrouping') { $val = $self->{config}->{values_for_lists}->{$attr}; }
                    when ('sendmailMTAAliasValue') {
			            $attr = $self->{config}->{values_for_lists}->{list_member};
                        if ($self->{config}->{general}->{verify_group_members} == 1) {
                            $val = $self->_get_member_value_sendmailMTA($val);
                        }else{
                            $val = $self->_get_member_value_sendmailMTA_no_verify($val);
                        }
                        $has_members = ( $val != 0 );
                    }
                }
                $dest_entry->add( $attr => $val, 
                );
            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: [' 
                          . $_
                          . '] Doesnt exist or is empty'
                    }
                );
            }
        }
            if ($has_members) {
            $self->{status}->{'new_entries'}++;
        }
        else {
            $self->{status}->{'errors'}++;
            $self->logger(
                {
                    level   => 'error',
                    message => 'Group entry '
                      . $dest_entry->dn
                      . ' must have at least one member.'
                }
            );
            $dest_entry = 0;

        }

    }
    else {    #update
        $self->logger(
            {
                level   => 'info',
                message => 'Updating entry: ' . $dest_entry->dn,
            }
        );

        foreach ( keys %{ $self->{config}->{list_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            my $value_dst =
              $dest_entry->get_value( $self->{config}->{list_map}->{$_},
                asref => 1 );
            my $attr = $self->{config}->{list_map}->{$_};
            my $val = $src_entry->get_value( $_, alloptions => 1, asref => 1 );
            $val = $val->{''};
            given ($attr) {
                when ('sAMAccountName') {
                    $attr = 'sendmailMTAKey';
                    $val = $src_entry->get_value($_);
                    $value_src = $val;
                }
                when ('homeDirectory') { $val = $self->{config}->{values_for_lists}->{$attr}; $value_src = $val;}
                when ('mailhost') { $val = $self->{config}->{values_for_lists}->{$attr}; $value_src = $val; }
                when ('sendmailMTAAliasGrouping') { $val = $self->{config}->{values_for_lists}->{$attr}; $value_src = $val;}
                when ('sendmailMTAAliasValue') {
			        $attr = $self->{config}->{values_for_lists}->{list_member};
                    if ($self->{config}->{general}->{verify_group_members} == 1) {
                        $val = $self->_get_member_value_sendmailMTA($val);
                    }else{
                        $val = $self->_get_member_value_sendmailMTA_no_verify($val);
                    }
                    $has_members = ( $val != 0 );
                }
            }
            if ($value_src) {
                if ($value_dst || $attr eq 'sendmailMTAKey') {
                    $dest_entry->replace( $attr => $val, );
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: [' . $attr . '] replaced'
                        }
                    );
                }
                else {
                    given ($attr) {
                        when ('sAMAccountName') {
                            $attr = 'sendmailMTAKey';
                            $val = $src_entry->get_value($_);
                        }
                        when ('homeDirectory') { $val = $self->{config}->{values_for_lists}->{$attr}; }
                        when ('mailhost') { $val = $self->{config}->{values_for_lists}->{$attr}; }
                        when ('sendmailMTAAliasGrouping') { $val = $self->{config}->{values_for_lists}->{$attr}; }
                        when ('sendmailMTAAliasValue') {
                            $attr = $self->{config}->{values_for_lists}->{list_member};
                            if ($self->{config}->{general}->{verify_group_members} == 1) {
                                $val = $self->_get_member_value_sendmailMTA($val);
                            }else{
                                $val = $self->_get_member_value_sendmailMTA_no_verify($val);
                            }
                            $has_members = ( $val != 0 );
                        }
                    }
                    $dest_entry->add( $attr => $val, );
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: [' . $attr . '] aggregated'
                        }
                    );
                }
            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: [' 
                          . $_
                          . '] Doesnt exists or is empty'
                    }
                );
            }
        }
        if ($has_members) {
            $self->{status}->{'upd_entries'}++;
        }
        else {
            $self->{status}->{'errors'}++;
            $self->logger(
                {
                    level   => 'error',
                    message => 'Group entry '
                      . $dest_entry->dn
                      . ' must have at least one member.'
                }
            );
            $dest_entry = 0;

        }
    }

    return $dest_entry;

}

=head2 update_usn

Update the USN value in local database.

=cut

sub update_usn {
    my $self    = shift;
    my $new_usn = shift;

    if ( $self->_src_is_ad ) {
        if ( $new_usn > $self->{usn} ) {
            $self->store_high_usn($new_usn);
            $self->logger(
                {
                    level   => 'debug',
                    message => 'Saving new usn value: [' . $new_usn . ']'
                }
            );
        }
    }

}

=head2 fetch_high_usn 

get high highestCommittedUSN saved in local database.

=cut

sub fetch_high_usn {
    my $self = shift;

    my $usn = $self->{db}->get("highestCommittedUSN");

    $self->{usn} = $usn;
}

=head2 store_high_usn 

save the usn in db

=cut

sub store_high_usn {
    my $self = shift;
    my $usn  = shift;

    $self->{db}->put( "highestCommittedUSN", $usn );
}

=head2 get_member_value 

Get member value for OpenLDAP groups

=cut

sub _get_member_value {
    my $self    = shift;
    my $members = shift;

    my $field_src  = $self->{config}->{general}->{filter};
    my $field_dest = $self->{config}->{general}->{rdn_user_field_dst};

    my @new_members = ();

    foreach my $user_dn (@$members) {
        my $result = $self->{src}->search(
            {
                base   => $self->{src}->base_people,
                scope  => "sub",
                filter => "(&(objectClass=*)"."(".$self->{config}->{general}->{rdn_user_field_src}."=".$user_dn.")".")", 
            }
        );
        my $user_id;
        for my $entry ( $result->entries ) {
            $user_id = $entry->get_value($field_dest);
        }

        my $member_dn =
          $field_dest . '=' . $user_id . ',' . $self->{dst}->base_people;

        my $exist = $self->{dst}->search(
            {
                base   => $self->{dst}->base_people,
                scope  => "sub",
                filter => "(&(objectClass=*)"."(".$self->{config}->{general}->{rdn_user_field_dst}."=".$user_id.")".")", 
            }
        );
        if ( $exist->entries ) {
            push( @new_members, $member_dn );
        }
        else {
            $self->logger(
                {
                    level   => 'warning',
                    message => 'Bad Member: ['
                      . $member_dn
                      . '] Doesnt exists or is empty'
                }
            );
        }
    }
    return \@new_members;

}

=head2 get_member_value_posixgroup 

Get member value for OpenLDAP groups using objectclass posixgroup

=cut

sub _get_member_value_posixgroup {
    my $self    = shift;
    my $members = shift;

    my $field_src  = $self->{config}->{general}->{filter};
    my $field_dest = $self->{config}->{general}->{rdn_user_field_dst};

    my $n_s_members;
    my $n_d_members;
    my @new_members = ();

    foreach my $user_dn (@$members) {
        my $result = $self->{src}->search(
            {
                base   => $self->{src}->base_people,
                scope  => "sub",
                filter => "(&(objectClass=*)"."(".$self->{config}->{general}->{rdn_user_field_src}."=".$user_dn.")".")", 
            }
        );
        my $user_id;
		my $user_uid;
        for my $entry ( $result->entries ) {
            $user_id = $entry->get_value($field_dest);
            $user_uid = $entry->get_value($field_src);
            $n_s_members++;
        }

        my $member_dn =
          $field_dest . '=' . $user_id . ',' . $self->{dst}->base_people;

        my $exist = $self->{dst}->search(
            {
                base   => $self->{dst}->base_people,
                scope  => "sub",
                filter => "(&(objectClass=*)"."(".$self->{config}->{general}->{rdn_user_field_dst}."=".$user_id.")".")", 
            }
        );
        if ( $exist->entries ) {
            push( @new_members, $user_uid );
            $n_d_members++;
        }
        else {
            $self->logger(
                {
                    level   => 'warning',
                    message => 'Bad Member: ['
                      . $member_dn
                      . '] Doesnt exists or is empty'
                }
            );
        }
    }

    $n_s_members = $n_s_members ? $n_s_members : 0;
    $n_d_members = $n_d_members ? $n_d_members : 0;
    
    $self->logger(
        {
            level   => 'info',
            message => "\n\t\t"
              . 'Miembros del grupo en AD: '
              . $n_s_members . "\n\t\t"
              . 'Miembros del grupo en OpenLDAP: '
              . $n_d_members . "\n\t\t"
              . 'Miembros que faltan en el Grupo: '
              . ($n_s_members - $n_d_members)
        }
    );
    return \@new_members;

}

=head2 get_member_value_sendmailMTA 

Get member value for OpenLDAP list using objectclass sendmailMTA

=cut

sub _get_member_value_sendmailMTA {
    my $self    = shift;
    my $members = shift;

    my $field_src  = $self->{config}->{list_map}->{mail};

    my $n_s_members;
    my $n_d_members;
    my @new_members = ();

    foreach my $user_dn (@$members) {
        my $result = $self->{src}->search(
            {
                base   => $self->{src}->base_people,
                scope  => "sub",
                filter => "(&(objectClass=*)"."(".$self->{config}->{general}->{rdn_user_field_src}."=".$user_dn.")".")", 
            }
        );

        my $user_id;
        for my $entry ( $result->entries ) {
            $user_id = $entry->get_value($field_src);
        }

        my $exist = $self->{dst}->search(
            {
                base   => $self->{dst}->base_people,
                scope  => "sub",
                filter =>
                "(&(objectClass=*)"."(".$field_src."=".$user_id.")".")", 
            }
        );
        if ( $exist->entries ) {
            push( @new_members, $user_id );
        }
        else {
            $self->logger(
                {
                    level   => 'warning',
                    message => 'Bad Member: ['
                      . $user_id
                      . '] Doesnt exists or is empty'
                }
            );
        }
    }

    $n_s_members = $n_s_members ? $n_s_members : 0;
    $n_d_members = $n_d_members ? $n_d_members : 0;
    
    $self->logger(
        {
            level   => 'info',
            message => "\n\t\t"
              . 'Miembros de la Lista en AD: '
              . $n_s_members . "\n\t\t"
              . 'Miembros de la Lista en OpenLDAP: '
              . $n_d_members . "\n\t\t"
              . 'Miembros que faltan en la Lista: '
              . ($n_s_members - $n_d_members)
        }
    );
    return \@new_members;

}

=head2 get_member_value_sendmailMTA_no_verify 

Get member value for OpenLDAP list using objectclass sendmailMTA

=cut

sub _get_member_value_sendmailMTA_no_verify {
    my $self    = shift;
    my $members = shift;

    my $field_src  = $self->{config}->{list_map}->{mail};

    my $n_s_members;
    my $n_d_members;
    my @new_members = ();

    foreach my $user_dn (@$members) {
        my $result = $self->{src}->search(
            {
                base   => $self->{src}->base_people,
                scope  => "sub",
                filter => "(&(objectClass=*)"."(".$self->{config}->{general}->{rdn_user_field_src}."=".$user_dn.")".")", 
            }
        );

        my $user_id;
        for my $entry ( $result->entries ) {
            $user_id = $entry->get_value($field_src);
            if ( ( $user_id eq '' ) || ( $user_id eq 'undef' ) ) {
                if ($entry->get_value('mailNickname') eq '') {
                     $user_id = $entry->get_value('sAMAccountName').'@'.$self->{config}->{info}->{dominio};
                }else{
                     $user_id = $entry->get_value('mailNickname').'@'.$self->{config}->{info}->{dominio};
                }
            } 
        }
        if ($user_id) {
            push( @new_members, $user_id );
        }
    }

    $n_s_members = $n_s_members ? $n_s_members : 0;
    $n_d_members = $n_d_members ? $n_d_members : 0;
    
    $self->logger(
        {
            level   => 'info',
            message => "\n\t\t"
              . 'Miembros de la Lista en AD: '
              . $n_s_members . "\n\t\t"
              . 'Miembros de la Lista en OpenLDAP: '
              . $n_d_members . "\n\t\t"
              . 'Miembros que faltan en la Lista: '
              . ($n_s_members - $n_d_members)
        }
    );
    return \@new_members;
}

=head2 get_member_uid 

Get member uid for OpenLDAP groups using objectclass posixgroup

=cut

sub _get_member_uid {
    my $self    = shift;
    my $members = shift;

    my $field_src  = $self->{config}->{general}->{filter};

    my $n_s_members;
    my $n_d_members;
    my @new_members = ();

    foreach my $user_dn (@$members) {
        my $result = $self->{src}->search(
            {
                base   => $self->{src}->base_people,
                scope  => "sub",
                filter => "(&(objectClass=*)"."(".$self->{config}->{general}->{rdn_user_field_src}."=".$user_dn.")".")", 
            }
        );

		my $user_uid;
        
        for my $entry ( $result->entries ) {
            $user_uid = $entry->get_value($field_src);
            $n_s_members++;
        }


        push( @new_members, $user_uid );
        $n_d_members++;
    }

    $self->logger(
        {
            level   => 'info',
            message => "\n\t\t"
              . 'Miembros del grupo en AD: '
              . $n_s_members . "\n\t\t"
              . 'Miembros del grupo en OpenLDAP: '
              . $n_d_members . "\n\t\t"
              . 'Miembros que faltan en el Grupo: '
              . ($n_s_members - $n_d_members)
        }
    );
    return \@new_members;

}

=head2 _prepare_entry_user_posixAccount


=cut

sub _prepare_entry_user_posixAccount {
    my ( $self, $src_entry ) = @_;

    # Read the filter field for Active Directory.
    my $f_f_ad = $self->{config}->{general}->{filter};

    # Read the filter map for OpenLDAP.
    my $f_f_ol = $self->{config}->{person_map}->{$f_f_ad};

    my $value  = $src_entry->get_value($f_f_ad);
    my $filter = "($f_f_ol=$value)";

    my $result = $self->{dst}->search(
        {
            base   => $self->{dst}->{config}->{base},
            scope  => "sub",
            filter => $filter
        }
    );

    my $dest_entry =
        $result->count > 0
      ? $result->shift_entry
      : Net::LDAP::Entry->new;

    # prepare dn if empty
    unless ( $dest_entry->dn ) {
        my $field = $self->{config}->{general}->{rdn_user_field_dst};

        # Buscar el valor correspondiente a $field en la fuente.
        my $valor = $src_entry->get_value($field);
        $valor =~ s/,//g;
        my $dn    = $field . '=' . $valor . ',' . $self->{dst}->base_people;
        $dest_entry->dn($dn);
    }

    # prepare attrs if attr list is empty
    unless ( $dest_entry->attributes ) {
        $self->logger(
            {
                level   => 'info',
                message => 'New entry: ' . $dest_entry->dn,
            }
        );
        $self->{status}->{'new_entries'}++;

        my $objectClass = $self->{config}->{personObjectClass}->{"objectClass"};
        my @oc = split( / /, $objectClass );

        $dest_entry->add( objectClass => [@oc] );

        foreach ( keys %{ $self->{config}->{person_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            if ( $value_src ne '' || $_ eq 'uidNumber' || $_ eq 'gidNumber' ) {
                if ( $_ eq 'gidNumber' ) {
                    if ($self->{config}->{general}->{get_inc_uidN} == 1) {
                        $dest_entry->add( $self->{config}->{person_map}->{$_} =>
                            $self->{dst}->get_maintenance_gidNumber
                            ? $self->{dst}->get_maintenance_gidNumber
                            : $self->{dst}->get_people_gidNumber );
                        $self->{dst}->increase_maintenance_gidNumber;
                    }else{
                        $dest_entry->add(
                            $self->{config}->{person_map}->{$_} => 10000 + $self->{status}->{'new_entries'}, 
                        );
                    }
                }
                elsif ( $_ eq 'uidNumber' ) {
                    if ($self->{config}->{general}->{get_inc_uidN} == 1) {
                        $dest_entry->add(
                            $self->{config}->{person_map}->{$_} => $self->{dst}->get_maintenance_uidNumber
                            ? $self->{dst}->get_maintenance_uidNumber
                            : 100000 + int rand( 20000 - 10000 + 1 ),
                            'homeDirectory' => '/home/' . $src_entry->get_value('sAMAccountName'), 
                            quota => $self->{config}->{values_for_users}->{quota},
                            mailhost => $self->{config}->{values_for_users}->{mailhost},
                        );
                        if ( $self->{dst}->increase_maintenance_uidNumber ) {
                            $self->logger(
                                {
                                    level => 'info',
                                    message =>
                                      "Incrementando el uidNumber de mantenimiento",
                                }
                            );
                        }
                        else {
                            $self->logger(
                                {
                                    level => 'warning',
                                    message =>
                                      "Can't increment maintenance uidNumber"
                                }
                            );
                        }
                    }else{
                        $dest_entry->add(
                            $self->{config}->{person_map}->{$_} => 100000 + $self->{status}->{'new_entries'}, 
                            'homeDirectory' => '/home/' . $src_entry->get_value('sAMAccountName'), 
                            quota => $self->{config}->{values_for_users}->{quota},
                            mailhost => $self->{config}->{values_for_users}->{mailhost},
                        );
                    }
                }
                else {
                    $dest_entry->add( $self->{config}->{person_map}->{$_} =>
                          $src_entry->get_value($_) );
                }
            }
        }
    }
    else {    #update
        $self->logger(
            {
                level   => 'info',
                message => 'Updating entry: ' . $dest_entry->dn,
            }
        );
        $self->{status}->{'upd_entries'}++;
        foreach ( keys %{ $self->{config}->{person_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            my $value_dst =
              $dest_entry->get_value( $self->{config}->{person_map}->{$_},
                asref => 1 );

            if ($value_src) {
                if ($value_dst) {
                    $dest_entry->replace( $self->{config}->{person_map}->{$_} =>
                          $src_entry->get_value($_), );
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: ['
                              . $self->{config}->{person_map}->{$_}
                              . '] replaced'
                        }
                    );
                }
                else {
                    if ( $_ eq 'uidNumber' ) {
                        $dest_entry->replace(
                            'homeDirectory' => '/home/' . $src_entry->get_value('sAMAccountName'),
                            quota => $self->{config}->{values_for_users}->{quota},
                            mailhost => $self->{config}->{values_for_users}->{mailhost},
                        );
                    }
                    else {
                        $dest_entry->replace( $self->{config}->{person_map}->{$_} => $src_entry->get_value($_), 
                            'homeDirectory' => '/home/' . $src_entry->get_value('sAMAccountName'),
                            quota => $self->{config}->{values_for_users}->{quota},
                            mailhost => $self->{config}->{values_for_users}->{mailhost},
                          );
                    }
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: ['
                              . $self->{config}->{person_map}->{$_}
                              . '] replaced'
                        }
                    );
                }
            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: ['
                          . $_
                          . '] Doesnt exists or is empty'
                    }
                );
            }

        }
    }

    return $dest_entry;
}

=head2 _prepare_entry_user_posixAccount_EXAMPLE

prepare entry user for sync with EXAMPLE requirement

=cut

sub _prepare_entry_user_posixAccount_EXAMPLE {
    my ( $self, $src_entry ) = @_;

    # Read the filter field for Active Directory.
    my $f_f_ad = $self->{config}->{general}->{filter};

    # Read the filter map for OpenLDAP.
    my $f_f_ol = $self->{config}->{person_map}->{$f_f_ad};

    my $value  = $src_entry->get_value($f_f_ad);
    my $filter = "($f_f_ol=$value)";

    my $result = $self->{dst}->search(
        {
            base   => $self->{dst}->{config}->{base},
            scope  => "sub",
            filter => $filter
        }
    );

    my $dest_entry =
        $result->count > 0
      ? $result->shift_entry
      : Net::LDAP::Entry->new;

    # prepare dn if empty
    unless ( $dest_entry->dn ) {
        my $field = $self->{config}->{general}->{rdn_user_field_dst};

        # Buscar el valor correspondiente a $field en la fuente.
        my $valor = $src_entry->get_value($field);
        $valor =~ s/,//g;
        my $dn    = $field . '=' . $valor . ',' . $self->{dst}->base_people;
        $dest_entry->dn($dn);
    }

    # prepare attrs if attr list is empty
    unless ( $dest_entry->attributes ) {
        $self->logger(
            {
                level   => 'info',
                message => 'New entry: ' . $dest_entry->dn,
            }
        );
        $self->{status}->{'new_entries'}++;

        my $objectClass = $self->{config}->{personObjectClass}->{"objectClass"};
        my @oc = split( / /, $objectClass );

        $dest_entry->add( objectClass => [@oc] );

        foreach ( keys %{ $self->{config}->{person_map} } ) {
            my $value_src = $src_entry->get_value( $_, asref => 1 );
            if ($_ eq 'mail') {
                $value_src = $src_entry->get_value( $_ );
            }
            if ( $value_src ne '' || $_ eq 'uidNumber' || $_ eq 'gidNumber' || $_ eq 'sn' || $_ eq 'mail') {
                my $mail_new;
                given ($_) {
                    when ( 'gidNumber' ) {
                        $dest_entry->add( $self->{config}->{person_map}->{$_} => '500513' );
                    }
                    when ( $_ eq 'sn' && $value_src eq '' ) {
                        $dest_entry->add( $self->{config}->{person_map}->{$_} => $src_entry->get_value('sAMAccountName') );
                    }
                    when ( $_ eq 'mail' && $value_src eq '' ) {
                        $dest_entry->add( $self->{config}->{person_map}->{$_} => $src_entry->get_value('sAMAccountName').'@'.$self->{config}->{info}->{dominio} );
                    }
                    when ( $_ eq 'mail' && $value_src !~ /\@example.com.ve/ ) {
                        if ($src_entry->get_value('mailNickname') eq '') {
                            $mail_new = $src_entry->get_value('sAMAccountName').'@'.$self->{config}->{info}->{dominio};
                            $dest_entry->add( $self->{config}->{person_map}->{$_} => $mail_new );
                        }else{
                            $mail_new = $src_entry->get_value('mailNickname').'@'.$self->{config}->{info}->{dominio};
                            $dest_entry->add( $self->{config}->{person_map}->{$_} => $mail_new ); 
                        }
                        my $cv_entry = $self->aliases($value_src, $mail_new);
                        my $men = $cv_entry->update( $self->{dst}->{ldap} );
                        if ( $men->is_error ) {
                            my $error =
                                "An error occurred while trying to sync aliases entry: "
                              . $cv_entry->dn . "\n"
                              . $men->error . "\n"
                              . $men->code . "\n"
                              . $men->error_name . "\n"
                              . $men->error_text . "\n"
                              . $men->error_desc;

                            $self->logger(
                                {
                                    level   => 'error',
                                    message => $error
                                }
                            );
                            $self->{status}->{'errors'}++;
                        }
                        else {
                            $self->logger(
                                {
                                    level   => 'info',
                                    message => 'Sync aliases entry: ' . $cv_entry->dn
                                }
                            );
                        }
                    }
                    when ($objectClass =~ /Vacation/ && $objectClass =~ /CourierMailAccount/ && $_ eq 'cn') {
                        my $mailbox = &gethomedir($src_entry->get_value('sAMAccountName'))
                        ? &gethomedir($src_entry->get_value('sAMAccountName'))
                        : $self->{config}->{values_for_users}->{mailbox};
                        $dest_entry->add( mailbox => $mailbox,
                                          quota => $self->{config}->{values_for_users}->{quota},
                                          vacationActive => $self->{config}->{values_for_users}->{vacationActive},
                                          mailhost => $self->{config}->{values_for_users}->{mailhost},);
                    }
                    when ( 'uidNumber' ) {
                        my $sid = &ConvertSidToStringSid($src_entry->get_value('objectSid'));
                        $sid =~ /(\d*$)/;
                        $dest_entry->add(
                            $self->{config}->{person_map}->{$_} => ($1 + 500000),
                            'homeDirectory' => '/home/' . $src_entry->get_value('sAMAccountName')
                        );
                    }
                    default {
                        $dest_entry->add( $self->{config}->{person_map}->{$_} => $src_entry->get_value($_) );
                    }
                }
            }
        }
    }
    else {    #update
        $self->logger(
            {
                level   => 'info',
                message => 'Updating entry: ' . $dest_entry->dn,
            }
        );
        $self->{status}->{'upd_entries'}++;
        my $objectClass = $self->{config}->{personObjectClass}->{"objectClass"};
        my @oc = split( / /, $objectClass );

        $dest_entry->replace( objectClass => [@oc] );
        foreach ( keys %{ $self->{config}->{person_map} } ) {
            my $value_src = $src_entry->get_value($_);
            my $value_dst =
              $dest_entry->get_value( $self->{config}->{person_map}->{$_},
                asref => 1 );
            if ($value_src || $_ eq 'sn' || $_ eq 'mail') {
                if ($value_dst) {
                my $mail_new;
                    given ($_) {
                        when ( $_ eq 'sn' && $value_src eq '' ) {
                            $dest_entry->replace( $self->{config}->{person_map}->{$_} => $src_entry->get_value('sAMAccountName') );
                        }
                        when ( $_ eq 'mail' && $value_src eq '' ) {
                            $dest_entry->replace( $self->{config}->{person_map}->{$_} => $src_entry->get_value('sAMAccountName').'@'.$self->{config}->{info}->{dominio} );
                        }
                        when ( $_ eq 'mail' && $value_src !~ /\@example.com.ve/ ) {
                            if ($src_entry->get_value('mailNickname') eq '') {
                                $mail_new = $src_entry->get_value('sAMAccountName').'@'.$self->{config}->{info}->{dominio};
                                $dest_entry->replace( $self->{config}->{person_map}->{$_} => $mail_new );
                            }else{
                                $mail_new = $src_entry->get_value('mailNickname').'@'.$self->{config}->{info}->{dominio};
                                $dest_entry->replace( $self->{config}->{person_map}->{$_} => $mail_new ); 
                            }
                            my $cv_entry = $self->aliases($value_src, $mail_new);
                            my $men = $cv_entry->update( $self->{dst}->{ldap} );
                            if ( $men->is_error ) {
                                my $error =
                                    "An error occurred while trying to sync aliases entry: "
                                  . $cv_entry->dn . "\n"
                                  . $men->error . "\n"
                                  . $men->code . "\n"
                                  . $men->error_name . "\n"
                                  . $men->error_text . "\n"
                                  . $men->error_desc;

                                $self->logger(
                                    {
                                        level   => 'error',
                                        message => $error
                                    }
                                );
                                $self->{status}->{'errors'}++;
                            }
                            else {
                                $self->logger(
                                    {
                                        level   => 'info',
                                        message => 'Sync aliases entry: ' . $cv_entry->dn
                                    }
                                );
                            }
                        }
                        when ($objectClass =~ /Vacation/ && $objectClass =~ /CourierMailAccount/ && $_ eq 'cn') {
                            my $mailbox = &gethomedir($src_entry->get_value('sAMAccountName'))
                            ? &gethomedir($src_entry->get_value('sAMAccountName'))
                            : $self->{config}->{values_for_users}->{mailbox};
                            $dest_entry->replace( mailbox => $mailbox,
                                              quota => $self->{config}->{values_for_users}->{quota},
                                              vacationActive => $self->{config}->{values_for_users}->{vacationActive},
                                              mailhost => $self->{config}->{values_for_users}->{mailhost},);
                        }
                        default {
                            $dest_entry->replace( $self->{config}->{person_map}->{$_} => $src_entry->get_value($_) );
                        }
                    }
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: ['
                              . $self->{config}->{person_map}->{$_}
                              . '] replaced'
                        }
                    );
                }
                else {
                    my $mail_new;
                    given ($_) {
                        when ( 'gidNumber' ) {
                            $dest_entry->add( $self->{config}->{person_map}->{$_} => '500513' );
                        }
                        when ( $_ eq 'sn' && $value_src eq '' ) {
                            $dest_entry->add( $self->{config}->{person_map}->{$_} => $src_entry->get_value('sAMAccountName') );
                        }
                        when ( $_ eq 'mail' && $value_src eq '' ) {
                            $dest_entry->add( $self->{config}->{person_map}->{$_} => $src_entry->get_value('sAMAccountName').'@'.$self->{config}->{info}->{dominio} );
                        }
                        when ( $_ eq 'mail' && $value_src !~ /\@example.com.ve/ ) {
                            if ($src_entry->get_value('mailNickname') eq '') {
                                $mail_new = $src_entry->get_value('sAMAccountName').'@'.$self->{config}->{info}->{dominio};
                                $dest_entry->add( $self->{config}->{person_map}->{$_} => $mail_new );
                            }else{
                                $mail_new = $src_entry->get_value('mailNickname').'@'.$self->{config}->{info}->{dominio};
                                $dest_entry->add( $self->{config}->{person_map}->{$_} => $mail_new ); 
                            }
                            my $cv_entry = $self->aliases($value_src, $mail_new);
                            my $men = $cv_entry->update( $self->{dst}->{ldap} );
                            if ( $men->is_error ) {
                                my $error =
                                    "An error occurred while trying to sync aliases entry: "
                                  . $cv_entry->dn . "\n"
                                  . $men->error . "\n"
                                  . $men->code . "\n"
                                  . $men->error_name . "\n"
                                  . $men->error_text . "\n"
                                  . $men->error_desc;

                                $self->logger(
                                    {
                                        level   => 'error',
                                        message => $error
                                    }
                                );
                                $self->{status}->{'errors'}++;
                            }
                            else {
                                $self->logger(
                                    {
                                        level   => 'info',
                                        message => 'Sync aliases entry: ' . $cv_entry->dn
                                    }
                                );
                            }
                        }
                        when ($objectClass =~ /Vacation/ && $objectClass =~ /CourierMailAccount/ && $_ eq 'cn') {
                            my $mailbox = &gethomedir($src_entry->get_value('sAMAccountName'))
                            ? &gethomedir($src_entry->get_value('sAMAccountName'))
                            : $self->{config}->{values_for_users}->{mailbox};
                            $dest_entry->add( mailbox => $mailbox,
                                              quota => $self->{config}->{values_for_users}->{quota},
                                              vacationActive => $self->{config}->{values_for_users}->{vacationActive},
                                              mailhost => $self->{config}->{values_for_users}->{mailhost},);
                        }
                        when ( 'uidNumber' ) {
                            my $sid = &ConvertSidToStringSid($src_entry->get_value('objectSid'));
                            $sid =~ /(\d*$)/;
                            $dest_entry->add(
                                $self->{config}->{person_map}->{$_} => ($1 + 500000),
                                'homeDirectory' => '/home/' . $src_entry->get_value('sAMAccountName')
                            );
                        }
                        default {
                            $dest_entry->add( $self->{config}->{person_map}->{$_} => $src_entry->get_value($_) );
                        }
                    }
                    $self->logger(
                        {
                            level   => 'debug',
                            message => 'Attr: ['
                              . $self->{config}->{person_map}->{$_}
                              . '] replaced'
                        }
                    );
                }
            }
            else {
                $self->logger(
                    {
                        level   => 'warning',
                        message => 'Bad attr: ['
                          . $_
                          . '] Doesnt exists or is empty'
                    }
                );
            }

        }
    }

    return $dest_entry;
}

=head2 get_high_usn

Get highestCommittedUSN from ActiveDirectory

=cut

sub get_high_usn {
    my $self = shift;
    my $dse =
      $self->{src}->{server}->root_dse( attrs => ['highestCommittedUSN'] );
    my $usn = $dse->get_value('highestCommittedUSN') || die $@;
    return $usn;
}

=head2 black_list

Set/Get user defined black_list

    $sync->black_list(@list); 

    my @list = $sync->black_list;

=cut

sub black_list {
    my ( $self, @list ) = @_;

    if (@list) {
        $self->{black_list} = \@list;
    }
    else {
        return $self->{black_list};
    }
}

=head2 _black_list

return true if argument is in black list

=cut

sub _black_list {
    my $self       = shift;
    my $entry      = shift;
    my @black_list = qw/CN=Computers DnsUpdateProxy SUPPORT Administrator root
      WasPatrol EXCHANGE EXCH SERVER \$/;

    push @black_list, @{ $self->black_list } if $self->black_list;

    for (@black_list) {
        if ( $entry->dn =~ m/$_/ ) {
            return 1;
        }
    }

    return 0;
}

sub gethomedir {
    my $user = lc shift;
    
    my $deep = 4;
    my $root_dir = '/corp';

    my $hashstr = md5_base64($user);
    my $homedir = $root_dir;
    my $c = undef;
    for (my $i = 0; $i < $deep ; ++$i) {
        my $n = substr($hashstr, $i, 1);
        if (length($n)) { $c = $n; }
        if ($c =~ /[^\w]/) { $c = '_'; }
        $homedir .= '/' . $c;
    }
    $homedir .= '/' . $user;
    return $homedir
}

=head2 ConvertSidToStringSid 

Metodo escrito por el papito con ayuda de una 
copa de Vino.
Wed Aug 22 03:07:08 UTC 2012

=cut

sub ConvertSidToStringSid {
    my($sid) = @_;
    
    $sid or return;
    my($Revision, $SubAuthorityCount, $IdentifierAuthority0, $IdentifierAuthorities12, @SubAuthorities) =
        unpack("CCnNV*", $sid);
    my $IdentifierAuthority = $IdentifierAuthority0 ?
            sprintf('0x%04hX%08X', $IdentifierAuthority0, $IdentifierAuthorities12) :
            $IdentifierAuthorities12;
    $SubAuthorityCount == scalar(@SubAuthorities) or return;
    return "S-$Revision-$IdentifierAuthority-".join("-", @SubAuthorities);
}

=head2 aliases 

Method to create a new entry in another branch, when the domain of the mail field is different from example.com.ve

=cut

sub aliases {
    my ($self, $mail, $mail_new) = @_;

    my $filter_attr = $self->{config}->{aliases_map}->{sendmailMTAKey};

    my $filter = "($filter_attr=$mail)";

    my $result = $self->{dst}->search(
        {
            base   => $self->{dst}->{config}->{base},
            scope  => "sub",
            filter => $filter
        }
    );

    my $dest_entry =
        $result->count > 0
      ? $result->shift_entry
      : Net::LDAP::Entry->new;
      
    my $field = $self->{config}->{general}->{rdn_dn_aliases_dst};

    my $dn    = $field . '=' . $mail . ',' . $self->{dst}->base_aliases;
    $dest_entry->dn($dn);

    unless ( $dest_entry->attributes ) {
        my $objectClass = $self->{config}->{aliasesObjectClass}->{"objectClass"};
        my @oc = split( / /, $objectClass );
        $dest_entry->add( objectClass => [@oc] );

        foreach ( keys %{ $self->{config}->{aliases_map} } ) {
            given ($_) {
                when ( 'sendmailMTAMapName' ) {
                    $dest_entry->add( $self->{config}->{aliases_map}->{$_} => $self->{config}->{values_for_aliases}->{$_} );
                }
                when ( 'sendmailMTAMapValue' ) {
                    $dest_entry->add( $self->{config}->{aliases_map}->{$_} => $mail_new );
                }
                when ( 'mailhost' ) {
                    $dest_entry->add( $self->{config}->{aliases_map}->{$_} => $self->{config}->{values_for_aliases}->{$_} );
                }
                when ( 'homeDirectory' ) {
                    $dest_entry->add( $self->{config}->{aliases_map}->{$_} => $self->{config}->{values_for_aliases}->{$_} );
                }
                default {
                    $dest_entry->add( $self->{config}->{aliases_map}->{$_} => $mail );
                }
            }
        }
    }else{#update
        my $objectClass = $self->{config}->{aliasesObjectClass}->{"objectClass"};
        my @oc = split( / /, $objectClass );
        $dest_entry->replace( objectClass => [@oc] );

        foreach ( keys %{ $self->{config}->{aliases_map} } ) {
            my $v_dst = $dest_entry->get_value( $self->{config}->{aliases_map}->{$_}, asref => 1 );

            if ($v_dst) {
                given ($_) {
                    when ( 'sendmailMTAMapName' ) {
                        $dest_entry->replace( $self->{config}->{aliases_map}->{$_} => $self->{config}->{values_for_aliases}->{$_} );
                    }
                    when ( 'sendmailMTAMapValue' ) {
                        $dest_entry->replace( $self->{config}->{aliases_map}->{$_} => $mail_new );
                    }
                    when ( 'mailhost' ) {
                        $dest_entry->replace( $self->{config}->{aliases_map}->{$_} => $self->{config}->{values_for_aliases}->{$_} );
                    }
                    when ( 'homeDirectory' ) {
                        $dest_entry->replace( $self->{config}->{aliases_map}->{$_} => $self->{config}->{values_for_aliases}->{$_} );
                    }
                    default {
                        $dest_entry->replace( $self->{config}->{aliases_map}->{$_} => $mail );
                    }
                }
            }else{
                given ($_) {
                    when ( 'sendmailMTAMapName' ) {
                        $dest_entry->add( $self->{config}->{aliases_map}->{$_} => $self->{config}->{values_for_aliases}->{$_} );
                    }
                    when ( 'sendmailMTAMapValue' ) {
                        $dest_entry->add( $self->{config}->{aliases_map}->{$_} => $mail_new );
                    }
                    when ( 'mailhost' ) {
                        $dest_entry->add( $self->{config}->{aliases_map}->{$_} => $self->{config}->{values_for_aliases}->{$_} );
                    }
                    when ( 'homeDirectory' ) {
                        $dest_entry->add( $self->{config}->{aliases_map}->{$_} => $self->{config}->{values_for_aliases}->{$_} );
                    }
                    default {
                        $dest_entry->add( $self->{config}->{aliases_map}->{$_} => $mail );
                    }
                }
            }
        }
    }

    return $dest_entry;
    
}


=head1 AUTHOR

Walter Vargas, C<< <walter at covetel.com.ve> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-covetel-ldap-sync at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Covetel-LDAP-Sync>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Covetel::LDAP::Sync


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Covetel-LDAP-Sync>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Covetel-LDAP-Sync>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Covetel-LDAP-Sync>

=item * Search CPAN

L<http://search.cpan.org/dist/Covetel-LDAP-Sync/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 Walter Vargas.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1;    # End of Covetel::LDAP::Sync
