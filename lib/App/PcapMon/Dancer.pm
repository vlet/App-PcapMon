package App::PcapMon::Dancer;
use strict;
use warnings;
use Dancer ':syntax';
use constant {
    ACK  => 0x10,
    PUSH => 0x08,
    RST  => 0x04,
    SYN  => 0x02,
    FIN  => 0x01,
};

set show_errors => 1;
set logger      => "console";

my $res;

get '/' => sub {
    to_dumper($res);
};

post '/packet' => sub {
    my $data = from_json( request->body );
    debug( to_dumper($data) );
    my ( $b, $e ) = ( 0, 0 );
    $res = {
        pkts  => 0,
        bytes => 0,
    };
    foreach my $packet ( @{ $data->{data} } ) {
        $res->{pkts}++;
        $res->{bytes} += $packet->[0];
        $b = $packet->[1] if ( $b == 0 );
        $e = $packet->[1];
        if ( $packet->[3] == 6 ) {
            for my $flag ( RST, SYN, FIN ) {
                if ( $packet->[6] & $flag ) {
                    $res->{$flag}++;
                }
            }
        }
    }
    my $delta = ( $e - $b ) || 5;
    $res->{pkts}  = sprintf( "%.2f", $res->{pkts} / $delta );
    $res->{bytes} = sprintf( "%.2f", $res->{bytes} / $delta );
};

1;
