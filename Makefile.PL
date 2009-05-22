use ExtUtils::MakeMaker;

WriteMakefile(
	NAME                => 'Net::Wire10',
	VERSION_FROM        => 'lib/Net/Wire10.pm',
	PREREQ_PM           => {
		Digest::SHA1     => 0.0,
		Encode           => 0.0,
		IO::Socket       => 0.0,
		IO::Select       => 0.0,
		utf8             => 0.0,
		threads          => 0.0,
		threads::shared  => 0.0,
	},
);
