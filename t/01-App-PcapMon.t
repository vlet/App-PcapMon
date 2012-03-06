use strict;
use warnings;

use Test::More;

BEGIN { use_ok('App::PcapMon') }

subtest 'new' => sub {
    eval {
        my $app = App::PcapMon->new( dev => "eth0", post_url=>"http://127.0.0.1/test");
    };
    like $@, qr"don't have permission to capture on that device", "root permissions" ;
};

done_testing;
