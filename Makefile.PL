use inc::Module::Install;

name 'App-PcapMon';
all_from 'lib/App/PcapMon.pm';
install_script 'bin/pcapmon';

requires 'Carp';

test_requires 'Test::More';

WriteAll;
