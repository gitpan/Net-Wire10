use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
	module_name             => 'Net::Wire10',
	license                 => 'perl',
	dist_version_from       => 'lib/Net/Wire10.pm',
	build_requires => {
		'Test::More'         => 0.0,
	},
	requires => {
		'Digest::SHA1'       => 0.0,
		'Encode'             => 0.0,
		'Exporter'           => 0.0,
		'IO::Socket'         => 0.0,
		'IO::Select'         => 0.0,
		'utf8'               => 0.0,
		'threads'            => 0.0,
		'threads::shared'    => 0.0,
	},
	create_makefile_pl => 'traditional',
);

$builder->create_build_script();
