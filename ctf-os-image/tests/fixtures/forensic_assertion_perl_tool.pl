#!/usr/bin/perl
use strict;
use warnings;

use Cwd qw(abs_path getcwd);
use Digest::SHA qw(sha256_hex);
use File::Basename qw(dirname);
use File::Path qw(make_path);
use Getopt::Long qw(GetOptions);
use JSON::PP ();
use Fcntl qw(SEEK_SET);

my $PROTOCOL = 'ctfos.release.forensic.assertion.tool.v1';
my $EXECUTION_PROTOCOL = 'ctfos.forensic.assertion.execution.v1';
my $MAX_REQUEST_BYTES = 256 * 1024;
my $MAX_SOURCE_BYTES = 16 * 1024 * 1024;
my $ALGORITHM = 'perl-sysread';
my $JSON = JSON::PP->new->canonical(1)->ascii(1)->allow_nonref(1);

sub fail {
    die "$_[0]\n";
}

sub canonical_json {
    return $JSON->encode($_[0]) . "\n";
}

sub file_bytes {
    my ($path, $maximum) = @_;
    open my $stream, '<:raw', $path or fail('file_open_failed');
    my @before = stat($stream);
    fail('file_stat_failed') if !@before || $before[7] > $maximum;
    local $/;
    my $payload = <$stream>;
    close $stream or fail('file_close_failed');
    $payload = '' if !defined $payload;
    fail('file_size_changed') if length($payload) != $before[7];
    return $payload;
}

sub file_sha256 {
    my ($path) = @_;
    return sha256_hex(file_bytes($path, $MAX_SOURCE_BYTES));
}

sub safe_relative {
    my ($value) = @_;
    fail('relative_path_invalid')
        if !defined($value)
        || ref($value)
        || $value eq ''
        || $value =~ m{^/}
        || $value =~ /\\/
        || grep { $_ eq '' || $_ eq '.' || $_ eq '..' } split m{/}, $value;
    return $value;
}

sub output_path {
    my ($relative) = @_;
    $relative = safe_relative($relative);
    my $destination = getcwd() . '/' . $relative;
    make_path(dirname($destination), {mode => 0700});
    return $destination;
}

sub write_private {
    my ($relative, $payload) = @_;
    my $path = output_path($relative);
    open my $stream, '>:raw', $path or fail('output_open_failed');
    print {$stream} $payload or fail('output_write_failed');
    close $stream or fail('output_close_failed');
    chmod 0400, $path or fail('output_chmod_failed');
}

sub source_path {
    my ($relative) = @_;
    $relative = safe_relative($relative);
    my $root = abs_path('/challenge');
    fail('challenge_root_missing') if !defined $root;
    my $cursor = $root;
    for my $part (split m{/}, $relative) {
        $cursor .= '/' . $part;
        my @metadata = lstat($cursor);
        fail('source_missing') if !@metadata;
        fail('source_symlink_rejected') if -l _;
    }
    my $resolved = abs_path($cursor);
    fail('source_escape_rejected')
        if !defined($resolved)
        || index($resolved, $root . '/') != 0
        || !-f $resolved;
    return $resolved;
}

sub bounded_request {
    my ($relative) = @_;
    my $path = getcwd() . '/' . safe_relative($relative);
    my $payload = file_bytes($path, $MAX_REQUEST_BYTES);
    my $value = eval { $JSON->decode($payload) };
    fail('request_json_invalid') if $@ || ref($value) ne 'HASH';
    fail('request_not_canonical')
        if $payload ne canonical_json($value);
    return ($payload, $value);
}

sub exact_range {
    my ($source, $offset, $length, $expected_sha256) = @_;
    fail('pointer_invalid')
        if $offset !~ /^\d+$/
        || $length !~ /^\d+$/
        || $length < 1;
    open my $stream, '<:raw', $source or fail('source_open_failed');
    my @before = stat($stream);
    fail('source_not_bounded_regular')
        if !@before
        || !-f _
        || $before[7] > $MAX_SOURCE_BYTES
        || $offset + $length > $before[7];
    my $digest = Digest::SHA->new(256);
    $digest->addfile($stream);
    fail('source_hash_mismatch')
        if $digest->hexdigest ne $expected_sha256;
    sysseek($stream, $offset, SEEK_SET)
        or ($offset == 0) or fail('source_seek_failed');
    my $selected = '';
    while (length($selected) < $length) {
        my $chunk = '';
        my $read = sysread(
            $stream,
            $chunk,
            $length - length($selected),
        );
        fail('source_read_failed') if !defined $read;
        last if $read == 0;
        $selected .= $chunk;
    }
    my @after = stat($stream);
    close $stream or fail('source_close_failed');
    fail('source_binding_mismatch')
        if length($selected) != $length
        || join(':', @before[0, 1, 2, 7, 9, 10])
        ne join(':', @after[0, 1, 2, 7, 9, 10]);
    return ($selected, $before[7]);
}

my %option;
GetOptions(
    'expected-image-digest=s' => \$option{expected_image_digest},
    'expected-tool-version=s' => \$option{expected_tool_version},
    'corrupt-binding' => \$option{corrupt_binding},
    'probe=s' => \$option{probe},
    'request=s' => \$option{request},
    'observation=s' => \$option{observation},
    'artifact=s' => \$option{artifact},
) or fail('arguments_invalid');

my $executable = '/usr/bin/perl';
my $tool_version = file_sha256($executable);
fail('tool_version_mismatch')
    if !defined($option{expected_tool_version})
    || $option{expected_tool_version} ne $tool_version;
fail('image_digest_missing')
    if !defined($option{expected_image_digest});
my $fixture_path = abs_path($0);
fail('fixture_missing') if !defined $fixture_path;
my $fixture_sha256 = file_sha256($fixture_path);

if (defined $option{probe}) {
    fail('probe_paths_conflict')
        if defined($option{request})
        || defined($option{observation})
        || defined($option{artifact});
    write_private(
        $option{probe},
        canonical_json(
            {
                algorithm => $ALGORITHM,
                binding_mode => (
                    $option{corrupt_binding}
                    ? 'pointer_mismatch'
                    : 'exact'
                ),
                fixture_sha256 => $fixture_sha256,
                image_digest => $option{expected_image_digest},
                network => 'none',
                producer_executable => $executable,
                producer_executable_sha256 => $tool_version,
                protocol => $PROTOCOL,
                schema_version => 1,
                supported_pointer_kinds => ['file_range'],
                tool_version_sha256 => $tool_version,
            }
        ),
    );
    exit 0;
}

fail('execution_paths_missing')
    if !defined($option{request})
    || !defined($option{observation})
    || !defined($option{artifact});
my ($request_payload, $request) = bounded_request($option{request});
my $pointer = $request->{pointer};
my $tool = $request->{tool};
fail('pointer_invalid')
    if ref($pointer) ne 'HASH'
    || ($pointer->{kind} // '') ne 'file_range';
fail('execution_tool_binding_mismatch')
    if ref($tool) ne 'HASH'
    || ($tool->{tool_version_sha256} // '') ne $tool_version
    || ($tool->{runtime_image_digest} // '')
    ne $option{expected_image_digest};
my $source = source_path($pointer->{source_path});
my ($selected, $source_size) = exact_range(
    $source,
    $pointer->{offset_bytes},
    $pointer->{length_bytes},
    $pointer->{source_sha256},
);
my $private_artifact = canonical_json(
    {
        algorithm => $ALGORITHM,
        length_bytes => 0 + $pointer->{length_bytes},
        offset_bytes => 0 + $pointer->{offset_bytes},
        pointer_id => $pointer->{pointer_id},
        protocol => $PROTOCOL,
        range_hex => unpack('H*', $selected),
        range_sha256 => sha256_hex($selected),
        schema_version => 1,
        source_path => $pointer->{source_path},
        source_sha256 => $pointer->{source_sha256},
        source_size_bytes => 0 + $source_size,
    }
);
write_private($option{artifact}, $private_artifact);

my $artifact = $request->{artifact};
my $observation = $request->{observation};
my $command = $request->{command};
my $transport = $request->{transport_contract};
my $source_binding = $request->{source};
for my $value (
    $artifact,
    $observation,
    $command,
    $transport,
    $source_binding,
) {
    fail('request_binding_invalid') if ref($value) ne 'HASH';
}
my $pointer_sha256 = (
    $option{corrupt_binding}
    ? ('0' x 64)
    : $pointer->{sha256}
);
my $document = {
    artifact => {
        artifact_id => $artifact->{artifact_id},
        path => $artifact->{path},
        sha256 => sha256_hex($private_artifact),
        size_bytes => length($private_artifact),
    },
    capture => {
        capture_complete => JSON::PP::true,
        capture_error_code => undef,
        truncated => JSON::PP::false,
        truncation_known => JSON::PP::true,
    },
    command_argv_sha256 => $command->{argv_sha256},
    command_template_sha256 => $command->{template_sha256},
    execution_nonce_sha256 => $request->{execution_nonce_sha256},
    index_execution_evaluation_sha256 => (
        $request->{index_execution_evaluation_sha256}
    ),
    independence_family => $tool->{independence_family},
    observation_id => $observation->{observation_id},
    operator_spec_sha256 => $request->{operator_spec_sha256},
    plan_sha256 => $request->{plan_sha256},
    pointer_id => $pointer->{pointer_id},
    pointer_kind => $pointer->{kind},
    pointer_sha256 => $pointer_sha256,
    protocol => $EXECUTION_PROTOCOL,
    readiness_registry_sha256 => $request->{readiness_registry_sha256},
    receipt_id => $observation->{receipt_id},
    request_id => $request->{request_id},
    request_sha256 => sha256_hex($request_payload),
    run_id => $request->{run_id},
    runtime_image_digest => $tool->{runtime_image_digest},
    schema_version => 1,
    semantic_execution_contract_sha256 => (
        $request->{semantic_execution_contract_sha256}
    ),
    source_inventory_sha256 => $source_binding->{inventory_sha256},
    source_manifest_sha256 => $source_binding->{manifest_sha256},
    tool_id => $tool->{tool_id},
    tool_version_sha256 => $tool->{tool_version_sha256},
    transport => {
        clean_workspace => JSON::PP::true,
        evidence_read_only => JSON::PP::true,
        exit_code => 0,
        network_disabled => JSON::PP::true,
        orchestration_status => 'completed',
        timed_out => JSON::PP::false,
    },
    transport_execution_contract_sha256 => (
        $transport->{transport_execution_contract_sha256}
    ),
};
write_private($option{observation}, canonical_json($document));
