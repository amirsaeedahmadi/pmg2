package PMG::RuleDB::Disclaimer;

use strict;
use warnings;
use DBI;
use Digest::SHA;
use HTML::Parser;
use HTML::Entities;
use MIME::Body;
use IO::File;
use Encode qw(decode encode);

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::ModGroup;
use PMG::RuleDB::Object;;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4009;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'Disclaimer';
}

sub oisedit {
    return 1;
}

sub final {
    return 0;
}

sub priority {
    return 49;
}

my $std_discl = <<_EOD_;
This e-mail and any attached files are confidential and may be legally privileged. If you are not the addressee, any disclosure, reproduction, copying, distribution, or other dissemination or use of this communication is strictly prohibited. If you have received this transmission in error please notify the sender immediately and then delete this mail.<br>
E-mail transmission cannot be guaranteed to be secure or error free as information could be intercepted, corrupted, lost, destroyed, arrive late or incomplete, or contain viruses. The sender therefore does not accept liability for any errors or omissions in the contents of this message which arise as a result of e-mail transmission or changes to transmitted date not specifically approved by the sender.<br>
If this e-mail or attached files contain information which do not relate to our professional activity we do not accept liability for such information.
_EOD_

sub new {
    my ($type, $value, $ogroup, $top, $separator) = @_;

    my $class = ref($type) || $type;

    $value //= $std_discl;

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $self->{value} = $value;
    $self->{top} = $top;
    $self->{separator} = $separator;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;

    my $class = ref($type) || $type;

    defined($value) || die "undefined object attribute: ERROR";

    my $sth = $ruledb->{dbh}->prepare(
	"SELECT * FROM Attribut WHERE Object_ID = ?");

    $sth->execute($id);

    my $top = 0;
    my $separator = 1;

    while (my $ref = $sth->fetchrow_hashref()) {
	$top = $ref->{value} if $ref->{name} eq 'top';
	$separator = $ref->{value} if $ref->{name} eq 'separator';
    }

    $sth->finish();

    my $obj = $class->new(decode('UTF-8', $value), $ogroup, $top, $separator);

    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $value, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined object attribute: ERROR";
    defined($self->{value}) || die "undefined object attribute: ERROR";

    my $value = encode('UTF-8', $self->{value});
    if ($value =~ /^.{998,}$/m) {
	die "too long line in disclaimer - breaks RFC 5322!\n";
    }

    if (defined ($self->{id})) {
	# update

	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?",
	    undef, $value, $self->{id});

	for my $prop (qw(top separator)) {
	    $ruledb->{dbh}->do(
		"DELETE FROM Attribut WHERE Name = ? and Object_ID = ?",
		undef, $prop,  $self->{id});
	}
    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->ogroup, $self->otype, $value);

	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq');
    }

    for my $prop (qw(top separator)) {
	if (defined($self->{$prop})) {
	    $ruledb->{dbh}->do(
		"INSERT INTO Attribut (Value, Name, Object_ID) VALUES (?, ?, ?)",
		undef, $self->{$prop}, $prop,  $self->{id});
	}
    }

    return $self->{id};
}

sub add_data {
    my ($self, $entity, $data) = @_;

    $entity->bodyhandle || return undef;

    my $fh;

    # always use the decoded data
    if (my $path = $entity->{PMX_decoded_path}) {
	$fh = IO::File->new("<$path");
    } else {
	$fh = $entity->open("r");
    }

    return undef if !$fh;

    # in memory (we can't modify the file, because
    # a.) that would modify all entities (see ModGroup)
    # b.) bad performance
    my $body = new MIME::Body::InCore || return undef;

    my $newfh = $body->open ("w") || return undef;

    if ($self->{top}) {
	$newfh->print($data);
    }

    while (defined($_ = $fh->getline())) {
	$newfh->print($_); # copy contents
    }

    $newfh->print("\n"); # add final \n

    if (!$self->{top}) {
	$newfh->print($data);
    }

    $newfh->close || return undef;

    $entity->bodyhandle($body);

    return 1;
}

sub sign {
    my ($self, $entity, $html, $text, $logid, $rulename) = @_;

    my $found = 0;

    if ($entity->head->mime_type =~ m{multipart/alternative}) {
	foreach my $p ($entity->parts) {
	    $found = 1 if $self->sign ($p, $html, $text, $logid, $rulename);
	}
    } elsif ($entity->head->mime_type =~ m{multipart/}) {
	foreach my $p ($entity->parts) {
	    if ($self->sign ($p, $html, $text, $logid, $rulename)) {
		$found = 1;
		last;
	    }
	}
    } elsif ($entity->head->mime_type =~ m{text/(html|plain)}) {
	my $type = $1;
	my $cs = $entity->head->mime_attr("content-type.charset") // 'ascii';
	eval {
	    my $encoded = encode($cs, $type eq 'html' ? $html : $text, Encode::FB_CROAK);
	    $self->add_data($entity, $encoded);
	};
	# simply ignore if we can't represent the disclainer
	# with that encoding
	if ($@) {
	    syslog('info', "%s: adding disclaimer failed (rule: %s)", $logid, $rulename);
	} else {
	    syslog('info', "%s: added disclaimer (rule: %s)", $logid, $rulename);
	}
	$found = 1;
    } else {
	# do nothing - unknown format
    }

    return $found;
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets,
	$msginfo, $vars, $marks) = @_;

    my $rulename = encode('UTF-8', $vars->{RULE} // 'unknown');

    my $subgroups = $mod_group->subgroups($targets);

    foreach my $ta (@$subgroups) {
	my ($tg, $entity) = (@$ta[0], @$ta[1]);
	my $html;
	my $separator = $self->{separator} ? '<br>--<br>' : '<br>';
	if ($self->{top}) {
	    $html = PMG::Utils::subst_values ($self->{value}, $vars) . $separator;
	} else {
	    $html = $separator . PMG::Utils::subst_values ($self->{value}, $vars);
	}

	my $text = "";
	my $parser = HTML::Parser->new(
	    api_version => 3, text_h => [ sub {$text .= shift;}, "dtext" ]);

	my $tmp = $html;
	$tmp =~ s/\r?\n//g;
	$tmp =~ s/<br>/\n/g;

	$parser->parse($tmp);
	$parser->eof;

	$self->sign($entity, "$html\n", "$text\n", $queue->{logid}, $rulename);

	return;
    }
}

sub short_desc {
    my $self = shift;

    return "disclaimer";
}

sub properties {
    my ($class) = @_;

    return {
	disclaimer => {
	    description => "The Disclaimer",
	    type => 'string',
	    maxLength => 2048,
	},
	position => {
	    description => "Put the disclaimer at the specified position.",
	    type => 'string',
	    enum => ['start', 'end'],
	    optional => 1,
	    default => 'end',
	},
	'add-separator' => {
	    description => "If set to 1, adds a '--' separator between the disclaimer and the".
		" content. Set to 0 to prevent that.",
	    type => 'boolean',
	    optional => 1,
	    default => 1,
	},
    };
}

sub get {
    my ($self) = @_;

    return {
	disclaimer => $self->{value},
	position => $self->{top} ? 'start' : 'end',
	'add-separator' => $self->{separator} // 1,
    };
}

sub update {
    my ($self, $param) = @_;

    $self->{value} = $param->{disclaimer};
    if (defined($param->{position}) && $param->{position} eq 'start') {
	$self->{top} = 1;
    } else {
	delete $self->{top};
    }

    if (defined($param->{'add-separator'}) && $param->{'add-separator'} == 0) {
	$self->{separator} = 0;
    } else {
	delete $self->{separator};
    }
}

1;

__END__

=head1 PMG::RuleDB::Disclaimer

Add disclaimer.
