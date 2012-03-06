package App::PcapMon;
use strict;
use warnings;
use Carp qw(croak carp);
use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:protos);
use NetPacket::TCP;
use IO::Select;
use IO::Socket::INET;
use IO::Pipe;

our $VERSION = '0.01';

sub new {
    my ( $class, %p ) = @_;
    my ( $address, $netmask );
    my $err = undef;

    croak "undefined device"   unless ( $p{dev} );
    croak "undefined post_url" unless ( $p{post_url} );
    my ( $host, $port, $path ) =
      ( $p{post_url} =~ '^http://(.+?)(?:\:(\d+))?(/.+)$' );
    croak "undefined webserver name (malformed post_url?)" unless ($host);
    my $snaplen = ( exists $p{snaplen} ) ? $p{snaplen} : 1500;
    my $promisc = ( exists $p{promisc} ) ? $p{promisc} : 0;
    my $to_ms   = 0;

    if ( Net::Pcap::lookupnet( $p{dev}, \$address, \$netmask, \$err ) ) {
        croak $err;
    }

    my $pcap =
      Net::Pcap::open_live( $p{dev}, $snaplen, $promisc, $to_ms, \$err );
    if ( defined $err ) {
        croak "cant open_live: " . $err;
    }

    if ( exists $p{filter} ) {
        my $filter;
        Net::Pcap::compile( $pcap, \$filter, $p{filter}, 1, \$netmask )
          && croak "Cant compile filter";

        Net::Pcap::setfilter( $pcap, $filter )
          && croak 'Cant setup filter';
    }

    bless {
        pcap      => $pcap,
        dev       => $p{dev},
        host      => $host,
        port      => $port,
        path      => $path,
        poll_time => ( exists $p{poll_time} ) ? $p{poll_time} : 5,
        data      => [],
        buf       => "",
    }, $class;
}

sub decode_pkt {
    my ( $header, $packet ) = @_;
    my @res = ( $header->{len}, $header->{tv_sec}, $header->{tv_usec} );
    my $ip = NetPacket::IP->decode( eth_strip($packet) );
    push @res, $ip->{proto}, qq{"$ip->{src_ip}"}, qq{"$ip->{dest_ip}"};
    if ( $ip->{proto} == IP_PROTO_TCP ) {
        my $tcp = NetPacket::TCP->decode( $ip->{'data'} );
        push @res, $tcp->{flags};
    }
    return join ",", @res;
}

sub http_connect {
    my $self = shift;

    $self->{http} = IO::Socket::INET->new(
        PeerAddr => $self->{host},
        PeerPort => defined( $self->{port} ) ? $self->{port} : 80,
        Proto    => 'tcp',
        Blocking => 0,
    );
    $self->{sel}->add( $self->{http} );
}

sub read_http_response {
    my $self = shift;
    my $data;
    my $len = sysread $self->{http}, $data, 4096;
    if ( !defined $len ) {

        # Error while reading socket
        carp $!;
        $self->{sel}->remove( $self->{http} );
        $self->{http}->close;
        $self->{http} = undef;
    }
    elsif ( $len == 0 ) {

        # Closed connection, try to reconnect
        $self->{sel}->remove( $self->{http} );
        $self->{http}->close;
        $self->http_connect();
    }

    # TODO: analyse web-server response (errors and so on)
}

sub read_pipe {
    my $self = shift;
    my $data;
    sysread $self->{pipe}, $data, 4096
      or croak "pipe closed";
    $self->{buf} .= $data;

    while ( ( my $len = index( $self->{buf}, "\n" ) ) > 0 ) {
        $data = substr( $self->{buf}, 0, $len );
        $self->{buf} =
          ( length( $self->{buf} ) > $len + 1 )
          ? substr( $self->{buf}, $len + 1 )
          : "";
        push @{ $self->{data} }, [ split( /,/, $data ) ];
    }
    chomp( $self->{buf} );
}

sub post_data {
    my $self = shift;

    if ( !defined $self->{http} ) {
        $self->http_connect();
    }

    foreach my $h ( $self->{sel}->can_write(0) ) {
        next if ( $h != $self->{http} );

        # emulate to_json();
        my $data =
            '{"data":['
          . join( ',', map { '[' . join( ',', @$_ ) . ']' } @{ $self->{data} } )
          . ']}';
        $self->{data} = [];
        $data =
            "POST $self->{path} HTTP/1.1\r\n"
          . "Host: $self->{host}\r\n"
          . "Connection: Keep-Alive\r\n"
          . "Content-Type: application/json\r\n"
          . "Content-Length: "
          . length($data)
          . "\r\n\r\n"
          . $data;
        my $len = syswrite $self->{http}, $data;
        if ( defined($len) && $len != length($data) ) {
            $self->{outbuf} = substr( $data, $len );
        }
    }
}

sub run {
    my ($self) = @_;

    $self->{pipe} = IO::Pipe->new();
    my $pid;

    if ( $pid = fork() ) {
        $self->{pipe}->writer;
        local $SIG{PIPE} = sub { croak "pipe closed" };
        my $sel = IO::Select->new( $self->{pipe} );
        Net::Pcap::loop(
            $self->{pcap},
            0,
            sub {
                my ( undef, $header, $packet ) = @_;
                if ( $sel->can_write(1) ) {
                    syswrite $self->{pipe},
                      decode_pkt( $header, $packet ) . "\n";
                }
            },
            undef
        ) && croak "Cant do capture";
        Net::Pcap::close( $self->{pcap} );
    }
    elsif ( defined $pid ) {
        $self->{pipe}->reader;
        $self->{sel} = IO::Select->new( $self->{pipe} );
        $self->http_connect();

        local $SIG{ALRM} = sub {
            $self->post_data();
            alarm $self->{poll_time};
        };

        alarm $self->{poll_time};
        while (1) {

            my ( $r, $w ) = $self->{sel}->select(
                ( exists $self->{outbuf} && length( $self->{outbuf} ) > 0 )
                ? $self->{sel}
                : undef
            );
            if ( defined $r && @$r ) {
                foreach my $h (@$r) {
                    if ( defined $self->{http} && $h == $self->{http} ) {
                        $self->read_http_response();
                    }
                    elsif ( $h == $self->{pipe} ) {
                        $self->read_pipe();
                    }
                }
            }
            if ( defined $w && @$w ) {
                foreach my $h (@$w) {
                    if (   defined $self->{http}
                        && $h == $self->{http}
                        && exists $self->{outbuf}
                        && length( $self->{outbuf} ) > 0 )
                    {
                        my $len = syswrite $self->{http}, $self->{outbuf};
                        if ( defined $len && $len != length( $self->{outbuf} ) )
                        {
                            $self->{outbuf} = substr( $self->{outbuf}, $len );
                        }
                        elsif ( defined $len ) {
                            delete $self->{outbuf};
                        }
                    }
                }
            }
        }
    }
    else {
        croak "fork failed";
    }
}

1;
__END__

=head1 NAME

App::PcapMon - base class for pcapmon

=head1 SYNOPSIS

  use App::PcapMon;
  my $app = App::PcapMon->new(
    dev       => 'eth0',                            # net device
    filter    => 'tcp port 22',                     # filter string
    post_url  => 'http://127.0.0.1:8080/packet',    # URL to POST
    poll_time => 5,                                 # POST captured data every 5 sec
  );
  $app->run();

=head1 DESCRIPTION

Capture packets and send packets info with json format to specified URL via POST method

=head1 SEE ALSO

http://blog.truecrux.org/xxii

=head1 AUTHOR

Vladimir Lettiev, E<lt>crux@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Vladimir Lettiev

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.

=cut
