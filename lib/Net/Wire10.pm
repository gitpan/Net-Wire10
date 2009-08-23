package Net::Wire10;

use strict;
use warnings;
use IO::Socket;
use IO::Select;
use utf8;
use Encode;
use threads;
use threads::shared;
use vars qw($VERSION $DEBUG);

use constant {
	DEFAULT_PORT_NUMBER  => 3306,
	DEFAULT_TIMEOUT      => 30,
	DEFAULT_FLAGS        => 0,
};

$VERSION = '1.02';

use constant STREAM_BUFFER_LENGTH => 65536;
use constant MACKET_HEADER_LENGTH => 4;
use constant TIMEOUT_GRANULARITY => 1;

use base 'Exporter';
our @EXPORT = qw(DATA_TEXT DATA_BINARY);

BEGIN {
	package Net::Wire10;

	# Macket (MySQL messages) types.
	our %MACKET_NAMES = (
		   1 => 'HANDSHAKE',
		   2 => 'AUTHENTICATE',
		   4 => 'OK',
		   8 => 'ERROR',
		  16 => 'COMMAND',
		  32 => 'RESULT_SET_HEADER',
		  64 => 'COLUMN_INFO',
		 128 => 'EOF',
		 256 => 'ROW_DATA',
		 512 => 'MORE_DATA',
	);

	# Type of commands that can be sent to the server.
	# Only QUIT, QUERY and PING are currently used.
	our %COMMAND_NAMES = (
		"\x00" => 'SLEEP',
		"\x01" => 'QUIT',
		"\x02" => 'INIT_DB',
		"\x03" => 'QUERY',
		"\x04" => 'FIELD_LIST',
		"\x05" => 'CREATE_DB',
		"\x06" => 'DROP_DB',
		"\x07" => 'REFRESH',
		"\x08" => 'SHUTDOWN',
		"\x09" => 'STATISTICS',
		"\x0A" => 'PROCESS_INFO',
		"\x0B" => 'CONNECT',
		"\x0C" => 'PROCESS_KILL',
		"\x0D" => 'DEBUG',
		"\x0E" => 'PING',
		"\x0F" => 'TIME',
		"\x10" => 'DELAYED_INSERT',
		"\x11" => 'CHANGE_USER',
		"\x12" => 'BINLOG_DUMP',
		"\x13" => 'TABLE_DUMP',
		"\x14" => 'CONNECT_OUT',
		"\x15" => 'REGISTER_SLAVE',
		"\x16" => 'STMT_PREPARE',
		"\x17" => 'STMT_EXECUTE',
		"\x18" => 'STMT_SEND_LONG_DATA',
		"\x19" => 'STMT_CLOSE',
		"\x1A" => 'STMT_RESET',
		"\x1B" => 'SET_OPTION',
		"\x1C" => 'STMT_FETCH',
	);

	# Per-connection flags, some of which are sent to the
	# server during handshake to convey client capabilities.
	our %FLAG_NAMES = (
		0x00000001 => 'LONG_PASSWORD',
		0x00000002 => 'FOUND_ROWS',
		0x00000004 => 'LONG_FLAG',
		0x00000008 => 'CONNECT_WITH_DB',
		0x00000010 => 'NO_SCHEMA',
		0x00000020 => 'COMPRESS',
		0x00000040 => 'ODBC',
		0x00000080 => 'LOCAL_FILES',
		0x00000100 => 'IGNORE_SPACE',
		0x00000200 => 'PROTOCOL_41',
		0x00000400 => 'INTERACTIVE',
		0x00000800 => 'SSL',
		0x00001000 => 'IGNORE_SIGPIPE',
		0x00002000 => 'TRANSACTIONS',
		0x00004000 => 'RESERVED',
		0x00008000 => 'SECURE_CONNECTION',
		0x00010000 => 'MULTI_STATEMENTS',
		0x00020000 => 'MULTI_RESULTS',
		0x40000000 => 'SSL_VERIFY_SERVER_CERT',
		0x80000000 => 'REMEMBER_OPTIONS',
	);

	our %UTF8_COLLATIONS = (
		33 => 'UTF8_GENERAL_CI',
		83 => 'UTF8_BIN',
		192 => 'UTF8_UNICODE_CI',
		193 => 'UTF8_ICELANDIC_CI',
		194 => 'UTF8_LATVIAN_CI',
		195 => 'UTF8_ROMANIAN_CI',
		196 => 'UTF8_SLOVENIAN_CI',
		197 => 'UTF8_POLISH_CI',
		198 => 'UTF8_ESTONIAN_CI',
		199 => 'UTF8_SPANISH_CI',
		200 => 'UTF8_SWEDISH_CI',
		201 => 'UTF8_TURKISH_CI',
		202 => 'UTF8_CZECH_CI',
		203 => 'UTF8_DANISH_CI',
		204 => 'UTF8_LITHUANIAN_CI',
		205 => 'UTF8_SLOVAK_CI',
		206 => 'UTF8_SPANISH2_CI',
		207 => 'UTF8_ROMAN_CI',
		208 => 'UTF8_PERSIAN_CI',
		209 => 'UTF8_ESPERANTO_CI',
		210 => 'UTF8_HUNGARIAN_CI',
	);

	our %DATA_TYPES = (
		0 => 'TEXT',
		1 => 'BINARY',
	);

	# Enumerations that are currently not included here:
	#  * Server capabilities
	#  * Server language
	#  * Server status
	#  * Server error code
	#  * Server error state
	#  * SQL data types
	#  * Column flags
	#  * Collations (complete)

	# TODO: An enumeration with a 2xxx error code for each client-side error.

	sub _assign {
		no strict 'refs';
		my $pkg = caller() . '::';
		my $key = shift;
		my $value = shift;
		*{"$pkg$key"} = sub () { $value };
	}

	sub _make_constant {
		my $what = shift;
		my $prefix = shift;
		my $i = 0;
		while ((my $key, my $value) = each(%$what)) {
			_assign("$prefix$value", $key);
		}
	}

	sub _find_largest_uint {
		# Assumes the Perl compiler uses signed integers.
		my $cur = 0;
		my $next = 0;
		for (my $i = 0; $i <= 16; $i++) {
			$next += (0xff << ($i * 8));
			return $i if sprintf("%d", $next) < 0;
			$cur = $next;
		}
	}

	_assign("MAX_UINT_SIZE", _find_largest_uint);

	_make_constant(\%MACKET_NAMES, "MACKET_");
	_make_constant(\%COMMAND_NAMES, "COMMAND_");
	_make_constant(\%FLAG_NAMES, "FLAG_");
	_make_constant(\%UTF8_COLLATIONS, "");
	_make_constant(\%DATA_TYPES, "DATA_");
}

my %MACKET_NAMES = %{*MACKET_NAMES};
my %COMMAND_NAMES = %{*COMMAND_NAMES};
my %FLAG_NAMES = %{*FLAG_NAMES};
my %UTF8_COLLATIONS = %{*UTF8_COLLATIONS};
my %DATA_TYPES = %{*DATA_TYPES};

# Constructor
sub new {
	my $class = shift;
	my %args = @_;

	my $self = bless {
		host       => $args{host},
		port       => $args{port} || DEFAULT_PORT_NUMBER,
		database   => $args{database},
		user       => $args{user},
		password   => $args{password},
		timeout    => defined($args{timeout}) ? $args{timeout} : DEFAULT_TIMEOUT,
		flags      => $args{flags} || DEFAULT_FLAGS,
		debug      => $args{debug} || 0,
	}, $class;
	$self->_reset_connection_state;
	$self->_reset_command_state;
	share($self->{cancelling});
	return $self;
}

# Initializes the connection to the server.
# An error is raised by an inner class if already connected
sub connect {
	my $self = shift;
	$self->_connect;
	$self->_perform_handshake;
	$self->_perform_authentication;
}

# Sends an SQL query
sub query {
	my $self = shift;
	my $sql = shift;

	return $self->_execute_query($sql, 0);
}

# Sends an SQL query, but does not read any rows in the result set
sub stream {
	my $self = shift;
	my $sql = shift;

	return $self->_execute_query($sql, 1);
}

# Creates a prepared statement object.
sub prepare {
	my $self = shift;
	my $sql = shift;

	return Net::Wire10::PreparedStatement->new($self, $sql);
}

# Sends a wire protocol ping
sub ping {
	my $self = shift;

	$self->_check_streaming;
	$self->_check_connected;
	$self->_reset_command_state;
	$self->_reset_timeout;

	return $self->_execute_command(COMMAND_PING, '', undef);
}

# Close the database connection
sub disconnect {
	my $self = shift;
	my $socket = $self->{socket};
	my $select = $self->{io_select};

	eval {
		if ($socket) {
			if ($select) {
				if ($select->can_write(TIMEOUT_GRANULARITY)) {
					my $body = COMMAND_QUIT;
					$self->_send_mackets($body, 0, MACKET_COMMAND);
				}
			}
			$socket->close;
		}
	};
	warn $@ if $@;

	$self->_reset_command_state;
	$self->_reset_connection_state;

	return undef;
}

# Cancels a running query
sub cancel {
	my $self = shift;
	$self->{cancelling} = 1;
	return undef;
}

# Get the connection id
sub get_connection_id {
	my $self = shift;
	return $self->{server_thread_id};
}

# Get the server version string
sub get_server_version {
	my $self = shift;
	return $self->{server_version};
}

# Is the driver currently connected?
# If a fatal error has occurred, this will return false
sub is_connected {
	my $self = shift;
	return defined($self->{socket});
}

# Check if the error flag is set
sub is_error {
	my $self = shift;
	return $self->{error_code} ? 1 : undef;
}

# Get the error code
sub get_error_code {
	my $self = shift;
	return $self->{error_code};
}

# Get the error SQL state designation
sub get_error_state {
	my $self = shift;
	return $self->{error_state} ? $self->{error_state} : '';
}

# Get the error message
sub get_error_message {
	my $self = shift;
	return $self->{error_message};
}

# Reset the time remaining counter before executing a command
sub _reset_timeout {
	my $self = shift;
	if ($self->{timeout} == 0) {
		$self->{command_expire_time} = 0;
		return undef;
	}
	$self->{command_expire_time} = time + $self->{timeout};
	return undef;
}

# Return the number of seconds left before the current
# operation should time out
sub _check_time_remaining {
	my $self = shift;
	return 0 if $self->{command_expire_time} == 0;
	my $remaining = $self->{command_expire_time} - time;
	$self->_fatal_error("Timeout while receiving data") if $remaining < 1;
	return $remaining;
}

# Fail if not connected anymore, due for example to a fatal error
sub _check_connected {
	my $self = shift;
	$self->_fatal_error("Not connected") unless defined($self->{socket});
}

# Fail if currently connected to a streaming data reader
sub _check_streaming {
	my $self = shift;
	$self->_vanilla_error("Connection is busy streaming") if $self->{streaming};
}

# Connects to the database server
sub _connect {
	my $self = shift;

	$self->_vanilla_error("Already connected") if defined($self->{socket});

	# Connect timeout.
	$self->_reset_timeout;

	my $socket;
	printf "Connecting to: %s:%d/tcp\n", $self->{host}, $self->{port} if $self->{debug} & 1;
	$socket = IO::Socket::INET->new(
		Proto    => 'tcp',
		PeerAddr => $self->{host},
		PeerPort => $self->{port},
		Timeout  => $self->_check_time_remaining
	) or $self->_fatal_error("Couldn't connect to $self->{host}:$self->{port}/tcp: $@");
	$socket->autoflush(1);
	$socket->timeout(TIMEOUT_GRANULARITY);
	$self->{socket} = $socket;
	$self->{io_select} = new IO::Select($self->{socket});

	$self->_reset_command_state;
}

# When a fatal error occurs, tear down TCP
# connection and set command state to indicate error.
sub _fatal_error {
	my $self = shift;
	my $msg = shift;

	$self->disconnect;

	$self->{error_code} = -1 unless $self->{error_code};
	$self->{error_message} = $msg;

	die $self->{error_message};
}

# When a non-fatal error occurs, just throw it.
sub _vanilla_error {
	my $self = shift;
	my $msg = shift;

	$self->{error_code} = -1 unless $self->{error_code};
	$self->{error_message} = $msg;

	die $self->{error_message};
}

# Receives data from the network and reassembles fragmented packets
sub _receive_packet_data {
	my $self = shift;
	my $socket = $self->{socket};
	my $io_select = $self->{io_select};
	my $data;

	while ($self->_check_time_remaining) {
		# Cancel if requested.
		$self->_fatal_error("Query cancelled") if $self->{cancelling};
		# Ask every second if there is data to be read.
		my $ready = $io_select->can_read(TIMEOUT_GRANULARITY);
		# IO::Select sometimes returns undef instead of an empty array.
		last if defined($ready) && (scalar($ready) != 0);
	}

	$socket->recv($data, STREAM_BUFFER_LENGTH, 0);
	# If select said data is available, but it
	# was not, it means the connection was lost.
	$self->_fatal_error("Lost connection") if length($data) == 0;
	$self->_dump_packet($data);

	$self->_alloc_packet_buffer(\$data);
	$self->_add_to_packet_buffer(\$data);
}

# If we have an idea of how much data is arriving, or there is not
# enough room for the recently received chunk, allocate more memory
sub _alloc_packet_buffer {
	my $self = shift;
	my $data = shift;

	my $buflen = length($self->{packet_buffer});
	my $goal = defined($self->{packet_goal}) ? $self->{packet_goal} + MACKET_HEADER_LENGTH : 0;
	my $goal2 = length($$data) + $self->{packet_read};
	$goal = $goal2 if $goal2 > $goal;
	if ($buflen < $goal ) {
		$self->{packet_buffer} .= ' ' x ($goal - $buflen);
	}
}

# Add received data to packet buffer
sub _add_to_packet_buffer {
	my $self = shift;
	my $data = shift;
	substr $self->{packet_buffer}, $self->{packet_read}, length($$data), $$data;
	$self->{packet_read} += length($$data);
}

# Queue the whole mackets received
sub _queue_mackets {
	my $self = shift;
	my $packet = \$self->{packet_buffer};

	# Receive more data if the macket header cannot be read
	return undef if $self->{packet_read} < MACKET_HEADER_LENGTH;

	# As long as we can read a macket header
	while ($self->{packet_read} > MACKET_HEADER_LENGTH) {
		# Get the length of the next macket, plus header length.
		if (! defined($self->{packet_goal})) {
			my $pos = 0;
			# Cached to avoid repeated decoding.
			$self->{packet_goal} = Net::Wire10::Util::decode_my_uint($$packet, \$pos, 3) + MACKET_HEADER_LENGTH;
		}
		return undef if $self->{packet_read} < $self->{packet_goal};
		print "Shifting a new macket totalling " . $self->{packet_goal} . " bytes into the macket queue.\n" if $self->{debug} & 1;
		my $macket = { buf => substr($$packet, 0, $self->{packet_goal}, '') };
		unshift(@{$self->{macket_queue}}, $macket);
		$self->{packet_read} -= $self->{packet_goal};
		$self->{packet_goal} = undef;
	}

	return 1;
}

# Gets the next macket in the queue
sub _next_macket {
	my $self = shift;
	my $macket;

	# Receive data if necessary
	while (scalar(@{$self->{macket_queue}}) == 0) {
		$self->_receive_packet_data;
		print "Bytes in receive buffer: " . $self->{packet_read} . "\n" if $self->{debug} & 1;
		$self->_queue_mackets;
	}

	# Return first queued macket
	$macket = pop(@{$self->{macket_queue}});
	$self->_check_received_macket_type($macket);
	return $macket;
}

# Fail if driver is getting something completely
# different from what it expected
sub _check_received_macket_type {
	my $self = shift;
	my $macket = shift;
	my $expected = $self->{expected_macket};
	my $msg = "";
	my $type = $self->_derive_received_macket_type($macket);

	$self->_dump_macket($macket);

	# If this is a error macket set error information and return,
	# regardless of what caller expects (error mackets are always expected).
	if ($type == MACKET_ERROR) {
		$self->_parse_error_macket($macket);
		return undef;
	}

	if ($expected & MACKET_EOF) {
		return undef if ($type == MACKET_EOF);
		$msg .= "Expected EOF Macket, did not receive it!\n";
	}

	if ($expected & MACKET_HANDSHAKE) {
		return undef if ($type == MACKET_HANDSHAKE);
		$msg .= "Expected Handshake Initialization Macket, did not recieve it!\n";
	}

	if ($expected & MACKET_OK) {
		return undef if ($type == MACKET_OK);
		$msg .= "Expected OK Macket, did not receive it!\n";
	}

	if ($expected & MACKET_RESULT_SET_HEADER) {
		return undef if ($type == MACKET_RESULT_SET_HEADER);
		$msg .= "Expected Result Set Header Macket, dit not receive it!\n";
	}

	if ($expected & MACKET_COLUMN_INFO) {
		return undef if ($type == MACKET_COLUMN_INFO);
		$msg .= "Expected Column Info Macket, did not receive it!\n";
	}

	if ($expected & MACKET_ROW_DATA) {
		return undef if ($type == MACKET_ROW_DATA);
		$msg .= "Expected Row Data Macket, did not receive it!\n";
	}

	if ($expected & MACKET_MORE_DATA) {
		return undef if ($type == MACKET_MORE_DATA);
		$msg .= "Expected Fragmented Data Macket, did not receive it!\n";
	}

	$self->_fatal_error($msg);
}

# Lacking a proper indicator of message type in received mackets,
# try to figure out what type of macket it is based on circumstances
sub _derive_received_macket_type {
	my $self = shift;
	my $macket = shift;

	# If this is a error macket set error information and return
	if (ord(substr($macket->{buf}, MACKET_HEADER_LENGTH, 1)) == 0xff) {
		return $macket->{type} = MACKET_ERROR;
	}

	if ((length($macket->{buf}) < MACKET_HEADER_LENGTH + 9) && (ord(substr($macket->{buf}, MACKET_HEADER_LENGTH, 1)) == 0xFE)) {
		return $macket->{type} = MACKET_EOF;
	}

	if ((ord(substr($macket->{buf}, MACKET_HEADER_LENGTH, 1)) == 0) && (length($macket->{buf}) > MACKET_HEADER_LENGTH + 5)) {
		return $macket->{type} = MACKET_OK;
	}

	if ($self->_extract_macket_number($macket) == 0 && ! defined($self->{protocol_version})) {
		return $macket->{type} = MACKET_HANDSHAKE;
	}

	if (! defined($self->{no_of_columns})) {
		return $macket->{type} = MACKET_RESULT_SET_HEADER;
	}

	if ($self->{expected_macket} & MACKET_COLUMN_INFO) {
		return $macket->{type} = MACKET_COLUMN_INFO;
	}

	if ($self->{expected_macket} & MACKET_ROW_DATA) {
		return $macket->{type} = MACKET_ROW_DATA;
	}

	if ($self->{expected_macket} & MACKET_MORE_DATA) {
		return $macket->{type} = MACKET_MORE_DATA;
	}

	$self->_fatal_error("Unknown macket type received");
}

# Sends a message to the server
sub _send_mackets {
	my $self = shift;
	my $body = shift;
	my $nr = shift;
	my $type = shift;
	my $len = length($body);
	my $pos = 0;

	while ($len >= 0) {
		# The server terminates the connection if the fragmented mackets
		# (except the last, of course) are not 0xffffff bytes long.
		my $chunk_len = $len > 0xffffff ? 0xffffff : $len;
		$len = -1 if ($len == 0) or ($chunk_len < 0xffffff);
		$len -= $chunk_len;

		my $head_len = Net::Wire10::Util::encode_my_uint($chunk_len, 3);
		my $head_nr = Net::Wire10::Util::encode_my_uint($nr, 1);
		my $chunk = substr($body, $pos, $chunk_len);
		$type = MACKET_MORE_DATA if ($pos > 0);
		my $macket = { buf => $head_len . $head_nr . $chunk, type => $type };

		$self->_dump_macket($macket);

		my $socket = $self->{socket};
		die "Not connected" unless $socket;

		$socket->send($macket->{buf}, 0);
		$nr = ($nr + 1) % 256;
		$pos += $chunk_len;
	}
}

# Reads and interprets server handshake
sub _perform_handshake {
	my $self = shift;

	$self->{expected_macket} = MACKET_HANDSHAKE;

	my $macket = $self->_next_macket;

	# Server will send an error instead of greeting
	# if too many connection slots are filled.
	if ($macket->{type} == MACKET_ERROR) {
		$self->_fatal_error(sprintf(
			"Connect failed:\n  Error code: %d\n  Message: %s",
			$self->{error_code},
			$self->{error_message}
		));
	}

	# Skip the macket header as it has been processed by _next_macket().
	my $i = MACKET_HEADER_LENGTH;
	# Protocol version
	$self->{protocol_version} = ord substr $macket->{buf}, $i, 1;
	printf "\nProtocol Version: %d\n", $self->{protocol_version} if $self->{debug} & 1;

	# Quit if the protocol version does not match what the driver supports.
	if ($self->{protocol_version} != 10) {
		$self->_fatal_error("Only MySQL wire protocol 10 is supported at the moment\n");
	}

	$i += 1;
	# Server version
	my $string_end = index($macket->{buf}, "\0", $i);
	$self->_fatal_error("Could not decode server version.\n") if $string_end == -1;
	$string_end -= $i;
	$self->{server_version} = substr $macket->{buf}, $i, $string_end;
	printf "Server version: %s\n", $self->{server_version} if $self->{debug} & 1;
	$i += $string_end + 1;
	my $left = length($macket->{buf}) - $i;
	$self->_fatal_error("Server handshake message truncated.\n") if $left < 44;
	# Server thread id
	$self->{server_thread_id} = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$i, 4);
	printf "Server thread id: %d\n", $self->{server_thread_id} if $self->{debug} & 1;
	# Scramble buff, 1st part
	$self->{salt} = substr $macket->{buf}, $i, 8;
	# Enables the use of old passwords
	$self->{salt_old} = $self->{salt};
	# The salt part is 8 bytes long and there is a one byte filler after
	$i += 8 + 1;
	# Server_capabilities is not used at the moment
	my $server_caps = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$i, 2);
	printf "Server capabilities (ignored): 0x%x\n", $server_caps if $self->{debug} & 1;
	# Server_language is not used at the moment
	my $server_lang = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$i, 1);
	printf "Server language (ignored): %d\n", $server_lang if $self->{debug} & 1;
	# Server_status is not used at the moment
	my $server_status = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$i, 2);
	printf "Server status (ignored): 0x%x\n", $server_status if $self->{debug} & 1;
	# 13 byte filler
	$i += 13;
	# Scramble buff, 2nd part
	# The MySQL protocol documentation says that this part is 13 bytes long,
	# but the last byte seems to be a filler.  So we only read 12 bytes.
	$self->{salt} .= substr $macket->{buf}, $i, 12;
	printf "Salt: %s\n", $self->{salt} if $self->{debug} & 1;
	# Filler
	$i += 1;
}

# Sends authentication, waits for answer, resends
# response to challenge in old format if requested by server
sub _perform_authentication {
	my $self = shift;

	$self->_send_login_message;
	$self->{expected_macket} = MACKET_EOF + MACKET_OK;

	my $auth_result = $self->_next_macket;
	if ($auth_result->{type} == MACKET_ERROR) {
		$self->_fatal_error(sprintf(
			"Authentication failed with:\n  Error code: %d\n  Message: %s",
			$self->{error_code},
			$self->{error_message}
		));
	}
	if ($auth_result->{type} == MACKET_EOF) {
		$self->_send_old_password;
		$self->{expected_macket} = MACKET_OK;
		$auth_result = $self->_next_macket;
		if ($auth_result->{type} == MACKET_ERROR) {
			$self->_fatal_error(sprintf(
				"Authentication failed with:\n  Error code: %d\n  Message: %s",
				$self->{error_code},
				$self->{error_message}
			));
		}
	}
	print "Connected to database server\n" if $self->{debug} & 1;
}

# Sends new format client authentication
sub _send_login_message {
	my $self = shift;

	# Obligatory flags
	my $driver_flags =
		FLAG_LONG_PASSWORD +
		FLAG_LONG_FLAG +
		FLAG_CONNECT_WITH_DB +
		# Unsupported:  COMPRESS
		# Unsupported:  LOCAL_FILES
		FLAG_PROTOCOL_41 +
		# Unsupported:  SSL
		# Unsupported:  IGNORE_SIGPIPE
		FLAG_TRANSACTIONS +
		# Unsupported:  RESERVED
		FLAG_SECURE_CONNECTION;
		# Unsupported:  MULTI_STATEMENTS
		# Unsupported:  MULTI_RESULTS
		# Unsupported:  SSL_VERIFY_SERVER_CERT
		# Unsupported:  REMEMBER_OPTIONS

	# Optional flags
	my $customizable_flags =
		FLAG_FOUND_ROWS +
		FLAG_NO_SCHEMA +
		FLAG_ODBC +
		FLAG_IGNORE_SPACE +
		FLAG_INTERACTIVE;

	my $flags = $driver_flags | ($customizable_flags & $self->{flags});
	my $body .= Net::Wire10::Util::encode_my_uint($flags, 4);
	# Max macket size.  Completely disregarded by the server,
	# which just overflows macket data onto other mackets when
	# sending and accepts overflowed data when receiving.
	# See also note in _send_mackets().
	$body .= Net::Wire10::Util::encode_my_uint(0x01000000, 4);
	# Character set; hardcoded to UTF-8, used in _parse_column_info_macket().
	$body .= chr(UTF8_GENERAL_CI);
	# 23 bytes filler.
	$body .= "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	# Null-terminated: user name
	$body .= $self->{user} . "\0";
	if (defined($self->{password})) {
		$body .= "\x14" . Net::Wire10::Password->scramble($self->{password}, $self->{salt});
	} else {
		$body .= "\0";
	}
	if (defined($self->{database})) {
		# Documentation says there should be a filler here,
		# but other clients don't send that.
		#$body .= "\0";
		# Null-terminated: initial default database name.
		$body .= $self->{database};
		$body .= "\0";
	}
	$self->_send_mackets($body, 1, MACKET_AUTHENTICATE);
}

# Sends old format client authentication
sub _send_old_password {
	my $self = shift;
	my $body = Net::Wire10::Password32->scramble(
		$self->{password}, $self->{salt_old}, 1
	) . "\0";
	$self->_send_mackets($body, 3, MACKET_AUTHENTICATE);
}

# Execute a SQL command
sub _execute_query {
	my $self = shift;
	my $sql = shift;
	my $wantstream = shift;

	$self->_check_streaming;
	$self->_check_connected;
	$self->_reset_command_state;
	$self->_reset_timeout;
	$self->{streaming} = 1 if $wantstream;

	my $iterator = Net::Wire10::Results->new($self);
	$self->{streaming_iterator} = $iterator if $wantstream;

	# The protocol is configured to always use UTF-8 during handskake, to
	# avoid messing with all the local character sets.  Therefore any input
	# string needs to be automatically converted if it is not already UTF-8.
	utf8::upgrade($sql) if defined($sql) and not utf8::is_utf8($sql);

	printf "Executing query: %s%s\n", substr($sql, 0, 100), length($sql) >= 100 ? " ..." : "" if $self->{debug} & 1;

	$self->_execute_command(COMMAND_QUERY, $sql, $iterator);
	return $iterator;
}

# Send a protocol command message
sub _execute_command {
	my $self = shift;
	my $command = shift;
	my $param = shift;
	my $iterator = shift;

	# Abort early if the driver is no longer connected.
	$self->_check_connected;

	# Strip the utf8 flag from the string,
	# otherwise the socket send() complains.
	Encode::_utf8_off($param);

	# Send the SQL command
	my $body = $command . $param;
	$self->_send_mackets($body, 0, MACKET_COMMAND);
	$self->{expected_macket} = MACKET_OK | MACKET_RESULT_SET_HEADER;

	# Receive the result from the database
	my $macket = $self->_next_macket;

	if ($macket->{type} == MACKET_ERROR) {
		$self->{streaming} = 0;
		$self->_vanilla_error($self->{error_message});
	}
	if ($macket->{type} == MACKET_RESULT_SET_HEADER) {
		my $pos = MACKET_HEADER_LENGTH;
		$self->_parse_result_set_header_macket($macket, \$pos);
		$self->_retrieve_column_info($iterator);
		$self->_retrieve_results($iterator) unless $self->{streaming};
	}
	if ($macket->{type} == MACKET_OK) {
		$self->_parse_ok_macket($macket, $iterator);
		$self->_detach_results;
	}
}

# Reads and interprets result set header
sub _parse_result_set_header_macket {
	my $self = shift;
	my $macket = shift;
	my $pos = shift;

	$self->{no_of_columns} = $self->_decode_lcb_or_fail($macket->{buf}, $pos);
	printf "Number of columns: %d\n", $self->{no_of_columns} if $self->{debug} & 1;
	# Optionally the "extra" field is in the macket
	my $macket_length = length($macket->{buf}) - MACKET_HEADER_LENGTH;
	if ($macket_length - 1 > $pos) {
		my $extra = $self->_decode_lcb_or_fail($macket->{buf}, $pos);
		printf "Extra information (ignored): %d\n", $extra if $self->{debug} & 1;
	}
}

# Reads and stores error message, sql state and error code
sub _parse_error_macket {
	my $self = shift;
	my $macket = shift;

	if ($macket->{type} != MACKET_ERROR) {
		$self->_fatal_error("Expected error macket");
	}

	# skip macket header
	my $pos = MACKET_HEADER_LENGTH;
	# skip macket type
	$pos += 1;
	$self->_fatal_error("Truncated error macket") if length($macket->{buf}) < 2;
	# error code
	$self->{error_code} = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$pos, 2);
	# Documentation says there always is a SQLSTATE marker here,
	# but that is not true.
	my $sqlstate_marker = substr($macket->{buf}, $pos, 1);
	if ($sqlstate_marker eq '#') {
		# skip SQL state marker
		$pos += 1;
		# read SQL state
		$self->{error_state} = substr($macket->{buf}, $pos, 5);
		$pos += 5;
	}
	# message
	$self->{error_message} = substr($macket->{buf}, $pos);
	Encode::_utf8_on($self->{error_message});
}

# Reads column info and EOF, possibly
# interrupted at any point by an error from the server
sub _retrieve_column_info {
	my $self = shift;
	my @queue = ();
	my $macket;
	my $iterator = shift;

	$self->{expected_macket} = MACKET_COLUMN_INFO | MACKET_EOF;
	# Put all field mackets in the selected queue
	do {
		$macket = $self->_next_macket;
		if ($macket->{type} == MACKET_ERROR) {
			$self->_fatal_error("Server reported error while reading column info: ".$self->{error_message});
		}
		if ($macket->{type} == MACKET_COLUMN_INFO) {
			my $column_info = $self->_parse_column_info_macket($macket);
			push(@queue, $column_info);
		}
	} until ($macket->{type} == MACKET_EOF);
	if ($self->{no_of_columns} ne scalar @queue) {
		$self->_fatal_error(sprintf(
			"Server reported %d columns, but sent %d",
			$self->{no_of_columns},
			scalar @queue
		));
	}
	$iterator->{column_info} = \@queue;
	$self->_parse_eof_macket($macket, $iterator);
}

# Reads all rows in result set
sub _retrieve_results {
	my $self = shift;
	my $iterator = shift;

	# Put all row data in the selected queue
	while ($self->_retrieve_row_data($iterator)) {}
}

# Reads row data or EOF, possibly
# interrupted at any point by an error from the server
sub _retrieve_row_data {
	my $self = shift;
	my $iterator = shift;

	$self->{expected_macket} = MACKET_ROW_DATA + MACKET_EOF;
	my $macket = $self->_next_macket;

	if ($macket->{type} == MACKET_ERROR) {
		$self->_fatal_error("Server reported error while reading row data: ".$self->{error_message});
	}
	if ($macket->{type} == MACKET_ROW_DATA) {
		# Note: The manual does not specify how the server fragments data.
		# One possibility would be that if the server sends data that fits
		# exactly on a macket boundary, then sends an additional completely
		# empty macket, to allow the client to assume that a maxed out macket
		# means that more fragments will follow.  Another possibility would
		# be that the server expects the client to deduce whether more mackets
		# are coming based on the contents of each macket, since fragmented
		# mackets only occur for data mackets which have an additional length
		# indicator (for the field data) inside the macket.  For the usual
		# lack of documentation, the method used below is a guess.
		my $nasty = length($macket->{buf});
		while ($nasty == MACKET_HEADER_LENGTH + 0xffffff) {
			# Glue together to form proper macket
			# (with invalid macket_length).
			printf "Fragmented macket found, retrieving one more fragment macket.\n" if $self->{debug} & 1;
			$self->{expected_macket} = MACKET_MORE_DATA;
			my $next_macket = $self->_next_macket;
			if ($macket->{type} == MACKET_ERROR) {
				$self->_fatal_error("Server reported error while reading more row data: ".$self->{error_message});
			}
			$nasty = length($next_macket->{buf});
			# Remove header from next fragment.
			substr($next_macket->{buf}, 0, MACKET_HEADER_LENGTH, "");
			# Concatenate macket contents.
			$macket->{buf} .= $next_macket->{buf};
		}
		# Remove header from first fragment.
		substr($macket->{buf}, 0, MACKET_HEADER_LENGTH, "");
		printf "Unshifting %d bytes of row data onto queue.\n", length($macket->{buf}) if $self->{debug} & 1;
		push(@{$iterator->{row_data}}, $macket->{buf});
		# More data may be available.
		return 1;
	}
	if ($macket->{type} == MACKET_EOF) {
		# Read EOF macket
		$self->_parse_eof_macket($macket, $iterator);
		$self->_detach_results($iterator);
		# No more data available.
		return 0;
	}
}

# Disconnect result set from driver, must only be done after all results have been read
sub _detach_results {
	my $self = shift;
	my $iterator = shift;
	$iterator->{wire} = undef;
	$self->{streaming_iterator} = undef;
	$self->{streaming} = 0;
}

# Reads and interprets OK, saving the number of affected rows,
# the insert id, and the server message.  Returns the number of
# affected rows
sub _parse_ok_macket {
	my $self = shift;
	my $macket = shift;
	my $iterator = shift;

	# Because affected rows is a Length Coded Binary
	# we use pointers to the position in the macket.
	# The position is updated in each method called
	# to ensure that the macket is read correctly.
	# First, skip macket header and macket type.
	my $pos = MACKET_HEADER_LENGTH + 1;
	# Affected rows
	my $affected = $self->_decode_lcb_or_fail($macket->{buf}, \$pos);
	printf "\nAffected rows: %d\n", $affected if $self->{debug} & 1;
	# Insert id
	my $id = $self->_decode_lcb_or_fail($macket->{buf}, \$pos);
	printf "Insert id: %d\n", $id if $self->{debug} & 1;
	$self->_fatal_error("Truncated OK macket") if length($macket->{buf}) < 4;
	# Server status
	my $status = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$pos, 2);
	printf "Server status flags (ignored): 0x%x\n", $status if $self->{debug} & 1;
	# Warning count
	my $warnings = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$pos, 2);
	printf "Warning count: %d\n", $warnings if $self->{debug} & 1;
	# Message
	my $message = substr($macket->{buf}, $pos);
	Encode::_utf8_on($message);
	printf "Server message (ignored): %s\n", $message if $self->{debug} & 1;

	$iterator->{no_of_affected_rows} = $affected;
	$iterator->{insert_id} = $id;
	$iterator->{warnings} = $warnings;
}

# Reads and interprets EOF, saving relevant values.
sub _parse_eof_macket {
	my $self = shift;
	my $macket = shift;
	my $iterator = shift;

	my $pos = MACKET_HEADER_LENGTH + 1;
	$self->_fatal_error("Truncated EOF macket") if length($macket->{buf}) < 4;
	# Warning count
	my $warnings = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$pos, 2);
	printf "Warning count: %d\n", $warnings if $self->{debug} & 1;
	# Server status
	my $status = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$pos, 2);
	printf "Server status flags (ignored): 0x%x\n", $status if $self->{debug} & 1;

	$iterator->{warnings} = $warnings;
}

# Reads and interprets column information
sub _parse_column_info_macket {
	# Metadata always in UTF-8; see collation in _send_login_message().
	my $self = shift;
	my $macket = shift;

	# Skip the header.
	my $pos = MACKET_HEADER_LENGTH;
	# Catalog
	my $catalog = $self->_decode_string_or_fail($macket->{buf}, \$pos);
	Encode::_utf8_on($catalog);
	# DB
	my $db = $self->_decode_string_or_fail($macket->{buf}, \$pos);
	Encode::_utf8_on($db);
	# Table
	my $table = $self->_decode_string_or_fail($macket->{buf}, \$pos);
	Encode::_utf8_on($table);
	# Org_table
	my $orig_table = $self->_decode_string_or_fail($macket->{buf}, \$pos);
	Encode::_utf8_on($orig_table);
	# Name
	my $column = $self->_decode_string_or_fail($macket->{buf}, \$pos);
	Encode::_utf8_on($column);
	# Org_name
	my $orig_column = $self->_decode_string_or_fail($macket->{buf}, \$pos);
	Encode::_utf8_on($orig_column);
	# Filler
	$pos += 1;
	$self->_fatal_error("Truncated column info macket") if length($macket->{buf}) < 10;
	# Charset number
	my $collation = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$pos, 2);
	# Length
	my $display_length = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$pos, 4);
	# Column data type
	my $data_type = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$pos, 1);
	# Flags
	my $flags = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$pos, 2);
	# Decimal scale (for DECIMAL or NUMERIC data types)
	my $decimal_scale = Net::Wire10::Util::decode_my_uint($macket->{buf}, \$pos, 1);
	# Filler
	$pos += 2;
	# Optionally the default field is available in the macket
	my $macket_length = length($macket->{buf}) - MACKET_HEADER_LENGTH;
	if ($macket_length - 1 > $pos) {
		$self->{extra} = $self->_decode_lcb_or_fail($macket->{buf}, \$pos);
		print "Default (ignored): " . $self->{extra} if $self->{debug} & 1;
	}
	printf "Catalog (ignored):  %s\nSource Database:    %s\n".
		"Table:              %s\nColumn:             %s\nSource Table:       %s\nSource Column:      %s\n".
		"Collation:          %s\nData Type:          %s\nDecimal Scale:      %s\n",
		$catalog, $db, $table, $column, $orig_table, $orig_column,
		$collation, $data_type, $decimal_scale
	if $self->{debug} & 1;
	return {
		table => $table,
		column => $column,
		orig_database => $db,
		orig_table => $orig_table,
		orig_column => $orig_column,
		collation => $collation,
		data_type => $data_type,
		decimal_scale => $decimal_scale
	};
}

# Verify the integrity of a row data macket by checking for each
# field value that it is contained within the macket's total length
sub _field_value_exceeds_buffer {
	my $self = shift;
	my $buf = shift;
	my $pos = shift;
	my $len = length($buf);
	while ($pos < $len) {
		Net::Wire10::Util::skip_string($buf, \$pos);
	}
	return $pos - $len;
}

# Given a macket, extract serial number from its header
sub _extract_macket_number {
	my $self = shift;
	my $macket = shift;

	return ord(substr($macket->{buf}, 3, 1));
}

# Given a macket, extract length from its header
sub _extract_macket_length {
	my $self = shift;
	my $macket = shift;
	my $pos = 0;

	return Net::Wire10::Util::decode_my_uint($macket->{buf}, \$pos, 3);
}

# Wrap the decode_lcb library function in an error handler,
# catching errors and sending them to the driver's _fatal_error()
sub _decode_lcb_or_fail {
	my $self = shift;
	my $buf = shift;
	my $pos = shift;

	my $result = eval {
		return Net::Wire10::Util::decode_lcb($buf, $pos);
	};
	$self->_fatal_error($@) if $@;
	return $result;
}

# Wrap the decode_string library function in an error handler,
# catching errors and sending them to the driver's _fatal_error()
sub _decode_string_or_fail {
	my $self = shift;
	my $buf = shift;
	my $pos = shift;

	my $result = eval {
		return Net::Wire10::Util::decode_string($buf, $pos);
	};
	$self->_fatal_error($@) if $@;
	return $result;
}

# Resets the command execution status
sub _reset_command_state {
	my $self = shift;
	# Disconnect streaming iterator.
	$self->{streaming_iterator}->_detach if $self->{streaming_iterator};
	# Reset internal column counter.
	$self->{no_of_columns} = undef;
	# Reset error state.
	$self->{error_code} = undef;
	$self->{error_state} = undef;
	$self->{error_message} = '';
	# Reset cancel flag.
	$self->{cancelling} = 0;
}

# Reset entire connection
sub _reset_connection_state {
	my $self = shift;
	$self->{protocol_version} = undef;
	$self->{server_version} = undef;
	$self->{salt} = '';
	$self->{packet_buffer} = '';
	$self->{packet_goal} = undef;
	$self->{packet_read} = 0;
	$self->{socket} = undef;
	$self->{io_select} = undef;
	$self->{expected_macket} = undef;
	$self->{macket_queue} = [];
	$self->{command_expire_time} = undef;
}

# Dumps the packet to standard output, useful for debugging
sub _dump_packet {
	my $self = shift;
	return unless $self->{debug} & 4;
	my $packet = shift;
	my ($method_name) = (caller(1))[3];
	my $str = sprintf "\n%s():\n", $method_name;
	my $len = length($packet);
	my $skipped = 0;
	my $pos = -16;
	while ($packet =~ /(.{1,16})/sg) {
		$pos += 16;
		unless ($self->{debug} & 8) {
			if (($len > 528) && ($pos > 256) && ($len - $pos > 256)) {
				if (! $skipped) {
					print "\n\n" . ' ' x 25 . "... snip more data ...\n";
					$skipped = 1;
				}
				next;
			}
		}
		my $line = $1;
		$str .= join ' ', map {sprintf '%02X', ord $_} split //, $line;
		$str .= '   ' x (16 - length $line);
		$str .= '  ';
		$str .= join '', map {
			sprintf '%s', (/[\w\d\*\,\?\%\=\'\;\(\)\.-]/) ? $_ : '.'
		} split //, $line;
		print $str;
		$str = "\n";
	}
	print $str;
}

# Dumps the macket to standard output, useful for debugging.
sub _dump_macket {
	my $self = shift;
	return unless $self->{debug} & 2;
	my $macket = shift;
	my ($method_name) = (caller(1))[3];
	my $str = sprintf "\n%s():\n", $method_name;
	$str .= sprintf "  -> serial: %d\n", Net::Wire10::_extract_macket_number($self, $macket);
	$str .= sprintf "  -> length: %d\n", Net::Wire10::_extract_macket_length($self, $macket);
	my $type = $macket->{type};
	$str .= sprintf "  -> type:   %s\n", $Net::Wire10::MACKET_NAMES{$type};
	$str .= sprintf "  -> data:   ";
	my $len = length($macket->{buf});
	my $skipped = 0;
	my $pos = -16;
	while ($macket->{buf} =~ /(.{1,16})/sg) {
		$pos += 16;
		unless ($self->{debug} & 16) {
			if (($len > 528) && ($pos > 256) && ($len - $pos > 256)) {
				if (! $skipped) {
					print "\n\n" . ' ' x 25 . "... snip more data ...\n";
					$skipped = 1;
				}
				next;
			}
		}
		my $line = $1;
		$str .= ' ' x 13 if substr($str, -1, 1) eq "\n";
		$str .= join ' ', map {sprintf '%02X', ord $_} split //, $line;
		$str .= '   ' x (16 - length $line);
		$str .= '  ';
		$str .= join '', map {
			sprintf '%s', (/[\w\d\*\,\?\%\=\'\;\(\)\.-]/) ? $_ : '.'
		} split //, $line;
		print $str;
		$str = "\n";
	}
	print $str;
}



package Net::Wire10::Results;

use strict;
use warnings;
use Encode;

# Constructor
sub new {
	my $class = shift;
	my $wire = shift;
	return bless {
		wire => $wire,
		column_info => [],
		row_data => []
	}, $class;
}

# Gets next row as an array
sub next_array {
	my $self = shift;
	my @result;
	my $row;

	# Note: A die() from this context often brings an application down.
	#       For disconnected result sets, row data is integrity checked
	#       during query() to simplify error handling for applications.

	if ($self->{wire}) {
		# In streaming mode, fetch a row
		return undef unless $self->{wire}->_retrieve_row_data($self);
	}

	# Return unless there is another row available
	return undef if scalar(@{$self->{row_data}}) == 0;

	$row = pop(@{$self->{row_data}});
	my $pos = 0;
	for (my $i = 1; $i <= $self->get_no_of_columns; $i++) {
		my $fieldvalue = Net::Wire10::Util::decode_string($row, \$pos);
		my $collation = $self->{column_info}->[$i - 1]->{"collation"};
		$Net::Wire10::UTF8_COLLATIONS{$collation} and Encode::_utf8_on($fieldvalue);
		push @result, $fieldvalue;
	}

	return \@result;
}

# Gets next row as a hash
sub next_hash {
	my $self = shift;
	my $row = $self->next_array;
	return undef unless defined $row;
	my @cols = $self->get_column_names;
	my %result = map { $_ => shift(@{$row}) } @cols;
	return \%result;
}

# Retrieve and store remaining rows
sub spool {
	my $self = shift;
	return undef unless $self->{wire};
	$self->{wire}->_retrieve_results($self);
	return undef;
}

# Retrieve and dispose of remaining rows
sub flush {
	my $self = shift;
	while ($self->next_array) {};
	return undef;
}

# Get the number of columns
sub get_no_of_columns {
	my $self = shift;
	return scalar(@{$self->{column_info}});
}

# Get the names of the columns
sub get_column_names {
	my $self = shift;
	return map { $_->{column} } @{$self->{column_info}};
}

# Did the query return a set of results or not
sub has_results {
	my $self = shift;
	return $self->get_no_of_columns ? 1 : 0;
}

# Get the number of affected rows
sub get_no_of_affected_rows {
	my $self = shift;
	return $self->{no_of_affected_rows};
}

# Get the number of selected rows
sub get_no_of_selected_rows {
	my $self = shift;
	return 0 unless defined $self->{row_data};
	return scalar(@{$self->{row_data}});
}

# Get the insert id
sub get_insert_id {
	my $self = shift;
	return $self->{insert_id};
}

# Get the number of warnings
sub get_warning_count {
	my $self = shift;
	return $self->{warnings};
}



package Net::Wire10::PreparedStatement;

use strict;
use warnings;
use utf8;
use Encode;

# Constructor
sub new {
	my $class = shift;
	my $wire = shift;
	my $sql = shift;

	# Input is either iso8859-1 or Unicode, handle as Unicode internally.
	utf8::upgrade($sql) if defined($sql) and not utf8::is_utf8($sql);

	# Find all "?" placeholders in query.
	my @tokens = Net::Wire10::Util::tokenize($sql);

	return bless {
		wire => $wire,
		tokens => \@tokens,
		params => [],
	}, $class;
}

# Set a parameter at a given index to a given value.
sub set_parameter {
	my $self = shift;
	my $index = shift;
	my $value = shift;
	my $datatype = shift || Net::Wire10::DATA_TEXT;

	# If input is iso8859-1 or Unicode, handle as Unicode.
	utf8::upgrade($value) if defined $value and not (($datatype == Net::Wire10::DATA_BINARY) or utf8::is_utf8($value));

	# Store for later.  Placeholders are numbered beginning with 1.
	@{$self->{params}}[$index - 1] = $value;

	return undef;
}

# Clear a parameter at a given index, or all parameters if no index given.
sub clear_parameter {
	my $self = shift;
	my @indices = @_;

	@{$self->{params}} = [] unless scalar @indices > 0;
	foreach my $index (@indices) {
		@{$self->{params}}[$index - 1] = undef;
	}

	return undef;
}

# Return the number of ? tokens in the prepared statement.
sub get_marker_count {
	my $self = shift;
	return scalar grep(/^\?$/, @{$self->{tokens}});
}

# See note about split and whitespace in Net::Wire10::Util.
my $whitespace = qr/^[\ \r\n\v\t\f]$/;

# Probably degrades performance quite a bit, necessary due to server bug:
# http://bugs.mysql.com/bug.php?id=1337
my $workaround_bug_1337 = qr/^[0-9]+$/;

# Assemble and execute prepared statement.
sub _execute {
	my $self = shift;
	my $wantstream = shift;
	my $wire = $self->{wire};

	# Replace tokens with parameters.
	my $prepared = '';
	my $i = 0;
	my $has_charset = 0;
	foreach my $token (@{$self->{tokens}}) {
		# Look for a ? token.
		if ($token ne '?') {
			$prepared .= $token;
			# Look for character set associations for upcoming ? tokens.
			my $first = substr($token, 0, 1);
			$has_charset = 0 if $first !~ $whitespace;
			$has_charset = 1 if $first eq '_';
			# Fast-forward to next token.
			next;
		}

		# Fetch and quote parameter, or add NULL for undef.
		my $value = $self->{params}->[$i++];
		unless (defined($value)) {
			$prepared .= 'NULL';
			next;
		}
		$value = Net::Wire10::Util::quote($value) if $value !~ $workaround_bug_1337;

		# If input is binary, tell the database server that it's binary.
		# It usually doesn't matter much because binary data is usually
		# used in a binary context anyway, but it fixes various uncommon
		# scenarios such as doing a CONVERT on a binary string.
		$prepared .= '_binary' unless utf8::is_utf8($value) or $has_charset;

		# If input is binary, make sure that Perl doesn't try to translate it
		# from iso8859-1 (which it isn't) to Unicode when the string is joined
		# with actual Unicode text to form a MySQL query, which is a character
		# array of mixed text and binary data.
		Encode::_utf8_on($value) unless utf8::is_utf8($value);

		# Add parameter in place of token.
		$prepared .= $value;
	}

	print "Assembled statement: " . $prepared . "\n" if $wire->{debug} & 1;
	return $wire->stream($prepared) if $wantstream;
	return $wire->query($prepared);
}

# Run the prepared statement and spool results.
sub query {
	my $self = shift;
	return $self->_execute(0);
}

# Run the prepared statement and return a result object for streaming.
sub stream {
	my $self = shift;
	return $self->_execute(1);
}



package Net::Wire10::Util;

use strict;
use warnings;

use constant LCB_NULL       => 251;
use constant LCB_UINT16     => 252;
use constant LCB_UINT24     => 253;
use constant LCB_UINT64     => 254;
use constant UINT8_LENGTH   => 1;
use constant UINT16_LENGTH  => 2;
use constant UINT24_LENGTH  => 3;
use constant UINT32_LENGTH  => 4;
use constant UINT64_LENGTH  => 8;
my @LCB_LENGTHS             = ();
$LCB_LENGTHS[LCB_NULL]      = 0;
$LCB_LENGTHS[LCB_UINT16]    = UINT16_LENGTH;
$LCB_LENGTHS[LCB_UINT24]    = UINT24_LENGTH;
$LCB_LENGTHS[LCB_UINT64]    = UINT64_LENGTH;

# Encode a given uint into wire protocol format, return as string of given length.
sub encode_my_uint {
	my $uint = shift;
	my $wirelen = shift;

	return substr(pack('V', $uint), 0, $wirelen);
}

# Decode a wire protocol unsigned integer at given offset and length and advance buffer pointer.
sub decode_my_uint {
	my $buf = shift;
	my $pos = shift;
	my $nrbytes = shift;

	my @bytes = unpack('x' . $$pos . 'C' x $nrbytes, $buf);
	my $result = 0;
	for (my $i = 0; $i < $nrbytes; $i++) {
		$result += $bytes[$i] << ($i * 8);
	}
	$$pos += $nrbytes;

	return $result if $nrbytes <= Net::Wire10::MAX_UINT_SIZE;

	die 'Overflow while reading a large integer' if
		($nrbytes > Net::Wire10::MAX_UINT_SIZE + 1) or
		($bytes[-1] > 0x7f);

	return $result;
}

# Decode a wire protocol LCB-coded unsigned integer (length implicit) and advance buffer pointer.
sub decode_lcb {
	my $buf = shift;
	my $pos = shift;
	my $len = length($buf);
	my $msg = 'Reached end of input while decoding Length Coded Binary';

	die $msg if $$pos >= $len;
	my $head = ord substr(
		$buf,
		$$pos,
		UINT8_LENGTH
	);
	$$pos += UINT8_LENGTH;

	return undef if $head == LCB_NULL;
	return $head if $head < LCB_NULL;
	my $bytes = $LCB_LENGTHS[$head];
	die $msg if $$pos + $bytes >= $len;
	return decode_my_uint($buf, $pos, $bytes) if $head <= LCB_UINT64;
	# If we end up here, first byte equals 255, which is invalid.
	die 'Invalid First-Byte in Length Coded Binary: 255';
}

# Get string and seek to the position after it
sub decode_string {
	my $buf = shift;
	my $pos = shift;

	my $length = decode_lcb($buf, $pos);

	# Return some sort of a null indicator if the string is LCB_NULL.
	return undef unless defined $length;

	# Note:  Neither the result set header, nor the column info packets, has
	#        a field describing which character set the server has encoded the
	#        metadata such as column names in.  Also, the user can change the
	#        character set used by issuing various SQL statements.  In effect
	#        making it impossible to know at this point in the state machine
	#        which character set is being used without having either parsed user
	#        queries or having done a "SELECT character_set_results" automatically
	#        before each query is sent to the server.

	my $string = substr $buf, $$pos, $length;
	$$pos += $length;
	return $string;
}

# Skip string, seeking to the position after it
sub skip_string {
	my $buf = shift;
	my $pos = shift;

	my $length = decode_lcb($buf, $pos);

	# Do nothing if string is LCB_NULL.
	$$pos += $length if defined $length;

	return undef;
}

# Note: The manual does not specify how the server handles small comments
#       terminating in CR, NEL, VT, FF, LS or PS.  Only LF is recognized
#       below (a guess).
# Note: The manual states that small comments initiated with -- must be
#       followed by a whitespace or similar such that an arithmetic double
#       minus is not mistaken for a comment, but it does not specify exactly
#       which characters are permitted.  ASCII contol characters and the space
#       character are recognized below (a guess).
# Note: The manual does not indicate whether ? tokens are allowed inside
#       conditional code such as /*!...*/.  In the expression below
#       it is not allowed (a guess).
# Note: The manual does not indicate which ASCII and Unicode characters are
#       considered whitespace.  In the expression below, the ASCII characters
#       CR, LF, VT, HT, FF and 0x20 are recognized (a guess).
my $split = qr/
	# capture each part, which is either:
	(
		# small comment in double-dash or
		--[[:cntrl:]\ ].*(?:\n|\z) |
		# small comment in hash or
		\#.*(?:\n|\z) |
		# big comment in C-style or version-conditional code or
		\/\*(?:[^\*]|\*[^\/])*(?:\*\/|\*\z|\z) |
		# whitespace
		[\ \r\n\v\t\f]+ |
		# single-quoted literal text or
		'(?:[^'\\]*|\\(?:.|\n)|'')*(?:'|\z) |
		# double-quoted literal text or
		"(?:[^"\\]*|\\(?:.|\n)|"")*(?:"|\z) |
		# schema-quoted literal text or
		`(?:[^`]*|``)*(?:`|\z) |
		# else it is either sql speak or
		(?:[^'"`\?\ \r\n\v\t\f\#\-\/]|\/[^\*]|-[^-]|--(?=[^[:cntrl:]\ ]))+ |
		# bingo: a ? placeholder
		\?
	)
/x;

# Split a MySQL-specific SQL string into parts,
# looking for '?' prepared statement placeholders.
sub tokenize {
	my $query = shift;

	my @tokens = $query =~ m/$split/g;

	# Assertion to ensure that bugs get caught; it's a bug
	# if the above regexp does not capture all of the query.
	my $parsed = join('', @tokens);
	die "query parsing failed" if length($parsed) != length($query);

	return @tokens;
}

sub quote {
	my $string = shift;
	return 'NULL' unless defined $string;

	for ($string) {
		s/\\/\\\\/g;
		s/\0/\\0/g;
		s/\n/\\n/g;
		s/\r/\\r/g;
		s/'/\\'/g;
		s/"/\\"/g;
		s/\x1a/\\Z/g;
	}

	return "'$string'";
}

sub quote_identifier {
	my $identifier = shift;
	return 'NULL' unless defined $identifier;

	for ($identifier) {
		s/`/``/g;
	}

	return "`$identifier`";
}

sub quote_wildcards {
	my $string = shift;
	return undef unless defined $string;

	for ($string) {
		s/%/\\%/g;
		s/_/\\_/g;
	}

	return $string;
}



package Net::Wire10::Password;

use strict;
use warnings;
use Digest::SHA1;

sub scramble {
	my $class = shift;
	my $password = shift;
	my $hash_seed = shift;
	return '' unless $password;
	return '' if length $password == 0;
	return _make_scrambled_password($hash_seed, $password);
}

sub _make_scrambled_password {
	my $hash_seed = shift;
	my $password = shift;

	my $ctx = Digest::SHA1->new;
	$ctx->reset;
	$ctx->add($password);
	my $stage1 = $ctx->digest;

	$ctx->reset;
	$ctx->add($stage1);
	my $stage2 = $ctx->digest;

	$ctx->reset;
	$ctx->add($hash_seed);
	$ctx->add($stage2);
	my $result = $ctx->digest;
	return _my_crypt($result, $stage1);
}

sub _my_crypt {
	my $s1 = shift;
	my $s2 = shift;
	my $l = length($s1) - 1;
	my $result = '';
	for my $i (0..$l) {
		$result .= pack 'C', (unpack('C', substr($s1, $i, 1)) ^ unpack('C', substr($s2, $i, 1)));
	}
	return $result;
}



package Net::Wire10::Password32;

use strict;
use warnings;

sub scramble {
	my $class = shift;
	my $password = shift;
	my $hash_seed = shift;
	my $client_capabilities = shift;

	return '' unless $password;
	return '' if length $password == 0;

	my $hsl = length $hash_seed;
	my @out;
	my @hash_pass = _get_hash($password);
	my @hash_mess = _get_hash($hash_seed);

	my ($max_value, $seed, $seed2);
	my ($dRes, $dSeed, $dMax);
	if ($client_capabilities < 1) {
		$max_value = 0x01FFFFFF;
		$seed = _xor_by_long($hash_pass[0], $hash_mess[0]) % $max_value;
		$seed2 = int($seed / 2);
	} else {
		$max_value= 0x3FFFFFFF;
		$seed  = _xor_by_long($hash_pass[0], $hash_mess[0]) % $max_value;
		$seed2 = _xor_by_long($hash_pass[1], $hash_mess[1]) % $max_value;
	}
	$dMax = $max_value;

	for (my $i=0; $i < $hsl; $i++) {
		$seed  = int(($seed * 3 + $seed2) % $max_value);
		$seed2 = int(($seed + $seed2 + 33) % $max_value);
		$dSeed = $seed;
		$dRes = $dSeed / $dMax;
		push @out, int($dRes * 31) + 64;
	}

	if ($client_capabilities == 1) {
		# Make it harder to break
		$seed  = ($seed * 3 + $seed2  ) % $max_value;
		$seed2 = ($seed + $seed2 + 33 ) % $max_value;
		$dSeed = $seed;

		$dRes = $dSeed / $dMax;
		my $e = int($dRes * 31);
		for (my $i=0; $i < $hsl ; $i++) {
			$out[$i] ^= $e;
		}
	}
	return join '', map { chr $_ } @out;
}

sub _get_hash {
	my $password = shift;

	my $nr = 1345345333;
	my $add = 7;
	my $nr2 = 0x12345671;
	my $tmp;
	my $pwlen = length $password;
	my $c;

	for (my $i=0; $i < $pwlen; $i++) {
		my $c = substr $password, $i, 1;
		next if $c eq ' ' || $c eq "\t";
		my $tmp = ord $c;
		my $value = ((_and_by_char($nr, 63) + $add) * $tmp) + $nr * 256;
		$nr = _xor_by_long($nr, $value);
		$nr2 += _xor_by_long(($nr2 * 256), $nr);
		$add += $tmp;
	}
	return (_and_by_long($nr, 0x7fffffff), _and_by_long($nr2, 0x7fffffff));
}

sub _and_by_char {
	my $source = shift;
	my $mask   = shift;

	return $source & $mask;
}

sub _and_by_long {
	my $source = shift;
	my $mask = shift || 0xFFFFFFFF;

	return _cut_off_to_long($source) & _cut_off_to_long($mask);
}

sub _xor_by_long {
	my $source = shift;
	my $mask = shift || 0;

	return _cut_off_to_long($source) ^ _cut_off_to_long($mask);
}

sub _cut_off_to_long {
	my $source = shift;

	if ($] >= 5.006) {
		$source = $source % (0xFFFFFFFF + 1) if $source > 0xFFFFFFFF;
		return $source;
	}
	while ($source > 0xFFFFFFFF) {
		$source -= 0xFFFFFFFF + 1;
	}
	return $source;
}


1;
__END__

=pod

=head1 NAME

Net::Wire10 - Pure Perl driver for MySQL, Sphinx and Drizzle.

=head1 DESCRIPTION

Net::Wire10 is a Pure Perl connector that talks to MySQL, Sphinx and Drizzle servers.

Net::Wire10 implements the low-level network protocol, alias the MySQL wire protocol version 10, necessary for talking to one of the aforementioned servers without using an external client library such as for example libmysqlclient or libdrizzle.

=head1 SYNOPSIS

  use Net::Wire10;

  my $wire = Net::Wire10->new(
      host     => 'localhost',
      user     => 'test',
      password => 'test',
      database => 'test'
  );

  $wire->connect;

  # CREATE TABLE example
  $wire->query(
      "CREATE TABLE foo (id INT, message TEXT)"
  );

  # INSERT example
  $wire->query(
      "INSERT INTO foo (id, message) VALUES (1, 'Hello World')"
  );
  printf "Affected rows: %d\n", $wire->get_no_of_affected_rows;

  # SELECT example
  my $results = $wire->query("SELECT * FROM foo");
  while (my $row = $results->next_hash) {
    printf
      "Id: %s, Message: %s\n",
      $row->{id},
      $row->{message};
  }

  $wire->disconnect;

=head1 INSTALLATION

Net::Wire10 is installed like any other CPAN perl module:

  $ perl -MCPAN -e shell
  cpan> install Net::Wire10

For Perl installations where the CPAN module (used above) is missing, you can also just download the .tar.gz from this site and drop the B<Net> folder in the same folder as the Perl file you want to use the driver from.

Some (particularly commercial) Perl distributions may have their own package management systems.  Refer to the documentation that comes with your particular Perl distribution for details.

=head1 USAGE

From Perl you can begin using the driver like this:

  use Net::Wire10;

After that you can connect to a server and start interacting.

Take a look at SYNOPSIS for a complete code example, or individual examples below.

=head2 Example: connect

Connection parameters are specified in the constructor to Net::Wire10.  After constructing an instance using new(), call connect() to begin talking to the server.

  $wire = Net::Wire10->new(
    host     => $host,
    user     => $user,
    password => $password,
  );

  $wire->connect();

The most frequently used parameters are shown above.
For additional parameters, refer to L<new>.

=head2 Example: create table

  $wire->query(
    "CREATE TABLE foo (id INT, message TEXT)"
  );

=head2 Example: insert data

  $wire->query(
    "INSERT INTO foo (id, message) VALUES (1, 'Hello World')"
  );

=head2 Example: retrieve data

  my $results = $wire->query(
    "SELECT id, message FROM foo"
  );

Data is traversed in a row-by-row fashion.  To retrieve each row of data, call next_hash() or next_array():

  my $row = $results->next_hash;

Do so in a loop to process all rows:

  while (my $row = $results->next_hash) {
    printf
      "Id: %d, Message: %s",
      $row->{id},
      $row->{message};
  }

=head2 Example: disconnect

  $wire->disconnect;

=head1 FEATURES

=head2 Features in the I<Net::Wire10> driver

=head3 new

Creates a new driver instance using the specified parameters.

  use Net::Wire10;
  use strict;
  use warnings;

  # Connect to Sphinx server on localhost
  my $wire = Net::Wire10->new(
      host       => 'localhost',
      port       => 3307,
      user       => 'test',
      password   => 'test',
    );

The argument hash can contain the following parameters:

=over 4

=item host    

Host name or IP address of the server to which a connection is desired.

=item port

TCP port where the server daemon listens.  The port differs depending on the server type, so that you can have more than one type of server installed on the same machine.

  MySQL uses port 3306,
  Sphinx uses port 3307,
  Drizzle uses port 4427.

The default is 3306 (MySQL), which is the most commonly used at the moment.

Sphinx needs to be at least version 0.9.9-rc2 for SphinxQL to work.  There's more information about SphinxQL here: L<http://sphinxsearch.com/docs/current.html#sphinxql>.

=item database

Name of the initial default database, eg the database used for a query when that query does not specifically mention a database.  The server may deny login if a database is given and the user does not have the necessary privileges to access that database.

=item user

Username for identifying the service or user to the database server.  This will show up in the process list, which is useful if you need to see what or who is hogging resources on the server.

=item password

Password for authenticating the service or user to the database server.

=item timeout

How long to wait before a connection attempt fails, and also how long to wait before a query is aborted.

=item debug

Various informational messages will be printed to the console if a value of 1 is given.  The exchanged network protocol messages ("mackets") will be printed to the console if a value of 2 is given.  The exchanged TCP packets will be printed to the console if a value of 4 is given.

=back

=head3 connect

Establishes or re-establishes a connection to the server.

=head3 ping

Pings the daemon on the connected server over the wire protocol.

After connecting, a ping() is useful to ensure that the connection is still alive.  The current status of the connection can be looked up using is_connected().

=head3 query

The query() method transmits the specified SQL string to the server and obtains the response, including the full set of results.

A result set is returned.  The obtained result set will be disconnected from the driver.  Being disconnected means that after retrieving the result set, you can fire more queries or close the connection.

Use query() when a small amount of records is needed for use at an arbitrary later point in time.  If you want to stream data to a live result set, including large amounts of data, see stream().

=head3 stream

The stream() method transmits the specified SQL string to the server, and obtains initial information about the response, but does not begin downloading data.

A result set is returned.  The obtained result set will be live with the driver.  After retrieving the result set, you must traverse all of its rows before you can fire another query.

Use stream() for large result sets, as it has a smaller memory footprint compared to query().  If you want to download data to a disconnected result set, use query().

Note that stream() will lock the driver until the whole result set has been retrieved.  To fetch another set of results while streaming to a live result set, create another driver object.

Also note that if you are using MySQL with the default storage engine, MyISAM, the entire table on the server will be locked for the duration of the live result set, that is until all rows have been retrieved.

=head3 prepare

Given a SQL string, returns a prepared statement.

Prepared statements are useful for:

=over 4

=item Inserting binary data in the database.

For each parameter, an indication of whether the parameter should be considered text or binary data can be given.

=item Avoiding bugs that could lead to SQL injections.

Separating query logic and parameters can be beneficial in securing against SQL injections.  Because query parameters do not have to be manually quoted, there's less risk of forgetting to quote or using an insecure quoting mechanism.

=item Reusing query logic with multiple sets of parameters.

Prepared statements can be re-executed with a new set of parameters.

=back

Database and database object names cannot be parameterized, because schema identifiers need to be escaped in a different way than literal strings, and there is currently no additional marker implemented for this purpose.  Identifiers can be manually quoted using Net::Wire10::Util::quote_identifier().

=head3 cancel (thread safe)

Cancels the running query.  Safe to call asynchronously (thread safe).

  use threads;

  # abort on some condition (sleep for demonstration purposes)
  threads->create(sub {
    $wire->cancel if sleep 2;
  })->detach;

  # run query for 10 seconds (will be interrupted by above thread after 2 sec)
  query("SELECT SLEEP(10)");

Run the example above to see how cancel() works to interrupt the SLEEP(10) statement before it finishes, after only 2 seconds instead of the full 10.

Another common way to kill a running query is to create another connection to the server, if possible, and use KILL QUERY (or KILL CONNECTION for older servers).  Using the KILL commands require a number of things, for example that the server has available connection slots, server privileges, etc.

=head3 is_connected

Returns true after connect() has been called, for as long as no fatal errors has occurred.

After a fatal error, a successful call to connect() causes is_connected to return true once again.

=head3 is_error

Returns true if an error code and message is available from the server or the driver.

=head3 get_server_version

After connecting, this returns the server version.

=head3 get_connection_id

After connecting, this returns a unique identifier for the thread on the server that handles the current connection.

The connection identifier is useful for logging and debugging, killing queries or connections, for naming pseudo-temporary tables or other objects, and more.

=head3 disconnect

Transmits a goodbye message to the server to indicate intentions, then closes the underlying socket.

=head2 Features in the I<Net::Wire10::Results> iterator

A Net::Wire10::Results object is returned when calling query() or stream().  Depending on which was used to execute the SQL, either a disconnected result set or a live (streaming) result set is returned.

=head3 next_array

The next_array() method returns a whole row, with individual field values packed into an array.
C<undef> is returned once all rows has been extracted.

  while (my $row = $results->next_array) {
    printf
      "Value 1: %s Value 2: %s Value 3: %s\n",
      $row->[0],
      $row->[1],
      $row->[2];
  }

When the retrieved columns has been specifically named in the SELECT statement (rather than using the C<SELECT *> wildcard), the position of each individual field in result set rows are known, and next_array() can be used to access field values based on their position.

Column name and order for a C<SELECT *> query can be retrieved using get_column_names().

After calling next_array(), the row has been consumed.  There is currently no way to rewind and re-read a row, even for a disconnected result set.

=head3 next_hash

The next_hash() method returns a whole row, with individual field values packed into a hash.  The key of the hash is the name of the column that each field belongs to.
C<undef> is returned once all rows has been extracted.

  while (my $row = $results->next_hash) {
    printf
      "Id: %s Name: %s Data: %s\n",
      $row->{id},
      $row->{name},
      $row->{data};
  }

Using next_hash() instead of next_array() usually makes the code a bit more readable, especially in cases where a SELECT with column names is not nearby.

After calling next_hash(), the row has been consumed.  There is currently no way to rewind and re-read a row, even for a disconnected result set.

=head3 spool

Reads the remaining rows of the result set, in effect turning a streaming result set into a disconnected result set.

=head3 flush

Reads the remaining rows of the result set and discards them.  When done on a live result set, this frees the driver for use.

=head3 get_no_of_columns

Returns the number of columns in the set of results.

=head3 get_column_names

Return the names of the result set's columns as an array.

=head3 has_results

Returns true if the query returned a set of results.

=head3 get_no_of_affected_rows

Returns the number of rows influenced by the UPDATE, DELETE or similar query.

  my $affected = $wire->get_no_of_affected_rows;

=head3 get_no_of_selected_rows

Returns the number of rows in the result set of a SELECT or similar query.

  my $selected = $wire->get_no_of_selected_rows;

After consuming a row, the number of available rows will decrease, and get_no_of_selected_rows() will return one less.

Supported only for disconnected result sets, live/streaming result sets are unaware of the total number of records.  A streaming result set can be turned into a disconnected result set using spool(), after which the number of available rows becomes known.

=head3 get_insert_id

MySQL and Drizzle has the ability to choose unique key values automatically, by enabling auto_increment for a column.  When this happens, the newly assigned id value for the last inserted row is stored in this attribute.

=head3 get_warning_count

After a query, this returns the number of warnings generated on the server.  If the query is streaming to a live result set, an additional warning count is available after the last row of data has been read.

=head2 Features in I<Net::Wire10::PreparedStatement>

=head3 get_token_count

Returns the number of "?" tokens found in the SQL initially used to create the prepared statement.

=head3 set_parameter

Sets the parameter at a given index to a given value.  The index corresponds to the relative position of a "?" marker in the prepared statement, with the first "?" marker being 1.

  $ps->set_parameter(2, 'Hello World');

There is no need to quote the parameter value, this is done automatically.

Binary data such as for example JPEG image files can also be added:

  $ps->set_parameter(3, $bindata, DATA_BINARY);

If the last parameter is specified as DATA_BINARY, the value given is taken as a binary string.  Otherwise, the value is taken as either an iso8859-1 string or a Unicode string, depending on what Perl thinks about the string.

=head3 clear_parameter

Clears one or more parameters, or all parameters if nothing was specified.

  $ps->clear_parameter(1, 3);

=head3 query

Execute the prepared statement using the parameters previously set with set_parameter().
All results are spooled before the call returns.

=head3 stream

Execute the prepared statement using the parameters previously set with set_parameter().
As soon as the initial metadata arrives from the database server, the call returns, and the results can be traversed in a streaming fashion.

=head2 Error handling features

There are two kind of errors in Net::Wire10, fatal and non-fatal errors.
Fatal errors causes the connection to close, while non-fatal errors do not.

Non-fatal errors cause the active query to abort.

A query may also cause warnings and informational messages, these are per
default only reported summarily via get_warning_count().  The actual messages
can be retrieved out-of-band from the server with the SHOW WARNINGS command.

=head3 catching errors

All errors can be caught with an eval {} construct.
To differentiate between a fatal and a non-fatal error, use is_connected().

  # Create driver and connect
  $wire = Net::Wire10->new(host=>'localhost', user=>'test', password=>'test');
  $wire->connect;

  # Execute nonsensical query
  eval { $wire->query('Argle-bargle, glyp-glof?!'); };
  warn $@ if $@;
  print ($wire->is_connected ? "is" : "is not") . " connected.";

=head3 recognizing fatal errors

Here's a query that causes a fatal error:

  # Execute query that kills the current connection
  eval { $wire->query('KILL CONNECTION CONNECTION_ID()'); };
  warn $@ if $@;
  print ($wire->is_connected ? "is" : "is not") . " connected.";

After running the above code, it is necessary to reconnect the driver before doing additional work.

=head3 reconnecting

Once a fatal error has happened, it is trivial to reestablish a connection to the server.

  # Reconnect if necessary
  $wire->connect unless $wire->is_connected;

Notice that the connection id changes after this.

=head3 multiple jobs

If stability is sought, always wrap your code with guard blocks in reasonable spots.
For example:

  foreach $job (@processing_items) {
    # Process job
    eval {
      $wire->connect unless $wire->is_connected;
      $wire->query("SELECT ... interesting data ...");
      $wire->query("SELECT ... more interesting data ...");
      ... more processing ...
      $wire->query("UPDATE ... whatever ...");
    };
    # Handle errors
    warn "Failed to process item, continuing with next item: $@" if $@;
  }

In the above, if any of the jobs in processing_items fail, a warning is printed, and the program reconnects (if necessary) and continues with the next job.

=head3 long term connections

If you have long-running jobs, always do a ping to check the connection after periods of inactivity.  For example:

  # Process some job, then sleep and repeat
  while (1) {
    eval { $wire->ping if $wire->is_connected; };
    eval {
      # If the ping (above) failed, reconnect
      $wire->connect unless $wire->is_connected;
      # Actual process code
      $wire->query("SELECT ... interesting data ...");
      $wire->query("SELECT ... more interesting data ...");
      ... more processing ...
      $wire->query("UPDATE ... whatever ...");
    };
    # Handle errors
    warn "Something went wrong: $@" if $@;
    # Wait a while before going again
    sleep 300;
  }

In the above, some job is run once every 5 minutes.  Before the job is run, the connection is checked with ping().  Should the connection have failed silently, the ping will provoke a fatal error and soon thereafter, connect() will reestablish the connection before processing starts.

These are much superior approaches to automatically reconnecting before firing each query (which some other drivers do).  Automatic reconnect schemes hides error messages, looses connection state, drops transactions, can cause half a transaction to complete, can cause table locks to be silently dropped, and similar malfunctions.

If you really want, you can amend the driver object with an extra version of query() (give it a different name) that automatically reconnects, or you can wrap the entire driver in your own object to the same effect, but I much recommend against it.  Proper guard blocks, with a connection check at the beginning (as above), is a much healthier practice.

=head3 retrieving warnings

Here's an example of how to retrieve warnings generated by the server.

  # Random query that emits a warning
  my $sql = "SELECT CAST('abc' AS CHAR(1))";

  # Run query on an existing connection
  my $res = $wire->query($sql);

  # Check for warnings
  if ($res->get_warning_count > 0) {
    my $warnings = $wire->query("SHOW WARNINGS");
    while (my $msg = $warnings->next_hash) {
      printf
        "Code: %d, Message: %s",
        $msg->{Code},
        $msg->{Message};
    }
  }

=head1 TROUBLESHOOTING

=head2 Supported operating system and Perl versions

This module has been tested on these platforms.

=over 4

=item * Windows Server 2008

with ActivePerl 5.10.0 build 1004, 32 and 64-bit

=back

Feel free to send in reports of success or failure using different platforms!

=head2 Unsupported features

The following features are not supported.

=head3 Protocols other than version 10

Only protocol version 10 is supported.

There are several revisions of version 10.  The only supported variant is the one described in the protocol documentation.

The documentation (at the time of this writing) covers MySQL Server version 4.1.  It is recommended to use the newest GA server release however, because version 4.1 has a number of Unicode bugs, particularly when using built-in SQL functions for text handling.

=head3 Transports other than TCP/IP

Shared memory is not supported.  Might be easy to add, my guess would be that it's just a ring buffer and one or two locks to synchronize readers and writers.

Named pipe is not supported.

Unix socket is not supported.

=head3 Character sets other than UTF-8

Result data is binary strings for binary data and UTF-8 strings for textual data.  Testing for a text versus a binary result value is accomplished using utf8::is_utf8().

SQL queries are given as strings, interpreted as either UTF-8 or iso8859-1 depending on what Perl thinks about the string.  When using prepared statements, binary data is also supported for parameters.  See set_parameter() for details.

It is possible to convert binary data to ASCII hex notation for inclusion directly in the query text:

  # Helper that converts binary to ASCII hex notation.
  sub raw_to_hex { return unpack("H*", shift); }

  # Convert to hex notation.
  $hex = raw_to_hex($binary_data);

  # Run a query containing hex data.
  my $res = $wire->query("SELECT $hex");

A more economical encoding than hex notation is BASE64.  If the server does not support BASE64 natively, a decoder can be added using for example this stored procedure: L<http://wi-fizzle.com/downloads/base64.sql>.

  # Contains helper that converts binary to BASE64 notation.
  use MIME::Base64 qw(encode_base64);

  # Convert to BASE64 notation.
  my $base64 = encode_base64($binary_data);

  # Run a query containing BASE64 data.
  my $res = $wire->query("SELECT BASE64_DECODE('$base64')");

An even more economical method is to use a prepared statement to send the binary data in its raw form.

=head3 Protocol compression via zlib

There is not much documentation regarding protocol compression, therefore it has not been implemented.

It is possible to add compression at the network level instead using a tunnel rather than the protocol's own support, similarly to stunnel described below, if network bandwidth is at a premium.

Another option is to selectively compress data with zlib before handing it off to the driver, and using the function UNCOMPRESS() to expand the data again once it reaches the server:

  # Contains helper that does zlib compression.
  use Compress::Zlib;

  # Compress some data.
  my $compressed = compress('Hello World!');

  # Create a prepared statement and bind the compressed data.
  my $ps = $wire->prepare('SELECT UNCOMPRESS(?)');
  $ps->set_parameter(1, $compressed, DATA_BINARY);

  # Run the query to decompress data on the server side.
  $res = $ps->query();

=head3 Verification of authenticity using SSL certificates

Verifying the server requires SSL support which is not currently implemented.

Verifying the client is not supported by the wire protocol.

=head3 SSL/TLS encrypted communication

There is not much documentation regarding protocol support for SSL/TLS, therefore it has not been implemented.

It is possible to add encryption at the network level by using a SSL/TLS wrapper such as "stunnel".

Stunnel provides a richer set of features than the current MySQL protocol supports, such as certificate-based authentication of the client in addition to the server.

Integrated support would be desirable because of simpler error handling and the possibility of performing key creation and certificate signing tasks via SQL.

=head3 Protocol-level prepared statements

The protocol design includes protocol-level support for server-side prepared statements.  When implemented at a protocol level, these are faster than regular statements.  Prepared statements execute faster because query parameters such as text does not need to be quoted before being sent to the server, and are not unquoted when arriving at the server.

Another performance benefit of prepared queries is that it is possible to perform multiple executions of the same query.  The query logic is sent and parsed only once, saving a bit of network bandwidth and CPU cycles.

The current protocol design does not allow you to clear a single parameter at a time, but forces you to clear all parameters at once.  When reusing a prepared statement for multiple executions, parameters that do not change from one execution to the next can therefore not be kept and has to be resent to the server for each execution of the query.  This inefficiency in the design of the protocol can in some cases be alleviated somewhat with a workaround involving user variables.

Some drivers do not pipeline the prepare, parameter, execute and deallocate steps, instead waiting for a response from the server after each step.  Such drivers may actually run some queries slower when using prepared statements.

A detail in the protocol specification is that results from non-prepared statements are pushed to the client, whereas results from prepared statements are pulled by the client.  The pull mechanism makes it possible to stop in the middle of a result set and cancel receiving any more rows.

Another, related detail in the protocol specification is that prepared statements are assigned a number each, whereas non-prepared statements are not.  Multiple prepared statements can therefore be active, running over the same connection at the same time, while only one non-prepared statement can be running at any one time.

In short, protocol-level prepared statements would be very nice to have, but are currently not implemented.  Protocol details are described in the manual, but with gaps in the documentation.

There is also a purely SQL-driven interface to prepared statements, using the PREPARE, EXECUTE and DEALLOCATE PREPARE commands.  The SQL-driven interface does not have the same performance benefits as the protocol-level one does.  It can however be useful for assembling SQL statements on the fly inside stored procedures and for checking SQL queries for correct syntax and identifiers without actually running the query.

There is also a client-side prepared statement interface in the driver, which it is highly recommended to use.

=head3 High-granularity streaming

Streaming data along the way as it is consumed or delivered by the client application can lead to dramatical decreases in memory usage.

Streaming outgoing data can be accomplished with server-side prepared statements, because the wire protocol allows prepared statement parameters to be sent one at a time, and even in chunks.  Chunking data presumably allows you to interleave data to different fields when sending a row to the server.  (See also L<Protocol-level prepared statements>.)

The driver API currently allows client applications to stream incoming data one row at a time.  The highest supported granularity for streaming is one whole row at a time.  Streaming at a higher granularity and interleaving chunks of incoming data is not part of the current protocol design.

Streaming incoming data in a row-by-row fashion is also known in some drivers as "use_result mode".

=head3 Server-side cursors

Cursors provide a way of keeping open, navigating and optionally modifying a result set on the server, rather than having to transfer the entire result set to the client.

MySQL Server supports only a particular class of cursors known as read-only, forward-only cursors.  As the name implies, this kind of cursor cannot be navigated (also called "scrolled") or modified.

The semantics are exactly the same as when streaming incoming data with the L<stream>() call.  With cursors however, the server automatically creates a temporary table behind the scenes from which the data is read, thereby always using extra resources for a temporary table, but consequently also releasing locks on original tables as soon as possible.

There is also a purely SQL-driven interface to cursors, which can be useful inside stored procedures.

Server-side cursors are part of the prepared statement protocol features (see above), and are therefore currently not supported.

=head3 Multiple statements per query

Currently unsupported.  Multiple statements can often cause more trouble than gain by making SQL injection (a security risk) much easier and in return providing diminutive performance gains when compared to other approaches.

If you want to run multiple queries, one method is to create two separate connections.  This can also give a performance boost, because one query does not wait for the other to finish.  Another related advantage is that multi-core servers can actually perform both queries simultaneously.

Two or more queries can be started simultaneously without resorting to multiple threads on the client.  This is done by starting the queries using the stream() call, which does not wait for the server to return data.

See also notes on connection pooling, which can be a useful technique to avoid initialization overhead when creating multiple connections.

=head3 Multiple result sets per query

Currently unsupported.  Support would be nice to have because MySQL Server requires this for executing stored procedures (but not stored functions) that digs out result set data: before the actual result set, MySQL Server will for any CALL statement generate an extra result set which contains some sort of status data about how the execution went.

Normally this kind of information is sent back in protocol status fields, but that differs when using CALL.  The implicit extra result set is very poorly documented, so it is hard to say if it is useful or not.  Many utilities seems to completely ignore it.

Multiple result sets per query is documented to be incompatible with prepared statements, but the reason why is not.

If you get the error message "can't return a result set in the given context", this is the server telling you that it would like to generate an extra result set, but can't because the connector does not support it.

=head3 Non-query related commands

Various non-query-related protocol commands that may be useful are not currently supported, for example COM_SHUTDOWN to initiate a server shutdown and COM_DEBUG to trigger the server into dumping a bunch of debug information.

=head2 Out of scope features

=head3 Connection pooling

Connection pooling can improve performance by removing the need for a TCP handshake and SSL/TLS handshake (for encrypted sessions) when opening a connection, and can also alleviate TIME_WAIT problems in environments with many short-lived connections.

There is no particular advantage to putting pooling code in the driver core itself, but a standard implementation that comes along with the driver would be nice.  Currently no such thing exists for this driver.

=head3 The LOAD DATA LOCAL INFILE client statement

Poorly documented and therefore unsupported.  If necessary, you can emulate the LOAD DATA LOCAL INFILE client statement using two other queries in unison, namely SELECT INTO DUMPFILE and LOAD DATA INFILE.

For optimal network performance, compress the data using zlib before sending it to the driver.  See also notes on compression further above.

  use Net::Wire10;

  # Connect to database server
  $wire = Net::Wire10->new(host=>'localhost', user=>'test', password=>'test');
  $wire->connect;

  # Go!
  upload_file('mydata.csv', '`test`.`sometable`');

  sub upload_file {
    my $filename = shift;
    my $table = shift;

    # Load file
    open(FILE, $filename) or die "$!";
    binmode FILE;
    $rawdata = join('', <FILE>);

    # Upload file to server
    my $ps = $wire->prepare("SELECT ? INTO DUMPFILE '/tmp/upload.csv'");
    $ps->set_parameter(1, $rawdata, DATA_BINARY);
    $ps->query;

    # Load data - notice that this is server-side, there is no LOCAL keyword.
    $wire->query("LOAD DATA INFILE '/tmp/upload.csv' INTO TABLE $table");

    # Reclaim disk space used by temporary file.
    # (Prohibited by some servers for security reasons; use an alternative method.)
    $wire->query("SELECT '' INTO DUMPFILE '/tmp/upload.csv'");
  }

When a similar solution was benchmarked, the performance was identical to a client-side version using the LOCAL feature (tested using the C API).

Be careful to escape data in the CSV file.  MySQL Server does not use the same CSV format as the de facto standard format use by Office applications.  One difference is that backslashes in CSV data are considered escape characters by MySQL Server.

When bulk loading data, it can be useful to temporarily disable keys with ALTER TABLE ... DISABLE KEYS, and/or to wrap the entire operation inside a transaction.

=head3 The DELIMITER client statement

Mostly useful for CLIs, and requires a lot of client-side SQL parsing.  Can be implemented in a CLI if necessary, there is no advantage to putting this in the driver.

=head2 Miscellaneous other limitations

Due to the way the Perl interpreter works, the following limitations may also apply.

=over 4

=item * Result sets limited to ~2 billion results on 32-bit Perl or ~9 quintillion results on 64-bit Perl.

=item * Field values limited to under 2 GiB on 32-bit Perl or under 8 EiB on 64-bit Perl.

=item * get_insert_id() values limited to ~2 billion on 32-bit Perl or ~9 quintillion on 64-bit Perl.

=back

If you need BIGINT UNSIGNED for AUTO_INCREMENT columns on 64-bit Perl (or INT UNSIGNED on 32-bit Perl), use "SELECT LAST_INSERT_ID()" rather than get_insert_id().

LAST_INSERT_ID() returns the sequence number as a string instead of as an integer, avoiding any overflow issues with Perl's built-in types.  You may also need to disable parsing of the insert_id protocol field in the driver to avoid an overflow error being thrown.

=head2 Known bugs

There should be a bug tracker where you can find known bugs.

Bugs in the design of the over-the-wire protocol may affect how the driver works. For example:

=over 4

=item * No character set info is sent with metadata such as column names, forcing the driver to assume that the client and result character sets are constant, when in fact they are not.

=item * Selecting data larger than max_packet_size server variable causes silent truncation (inserting does not).

=back

Refer to the MySQL issue tracker for more server and protocol issues.

Bugs and design issues in Perl itself may also affect the driver.  For example:

=over 4

=item * Using an alarm to invoke cancel() often does not work, especially on Windows (use a thread instead).

=item * Integer scalars are always signed.

=back

Bugs in IO::Socket or IO::Select may also affect the driver.

=head1 SEE ALSO

L<DBD::Wire10>

=head1 AUTHOR

Driver core hacked together by Kim Christensen and David Dindorp at Dubex A/S.
Password hashing routines by Hiroyuki OYAMA E, Japan.  

=head1 COPYRIGHT AND LICENCE

Copyright (C) 2002 and (C) 2009 as described in AUTHORS.

This is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 WARRANTY

Because this software is licensed free of charge, there is
absolutely no warranty of any kind, expressed or implied.

=cut
