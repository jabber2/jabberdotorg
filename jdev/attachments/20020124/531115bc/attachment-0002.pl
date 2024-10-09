#!/usr/bin/perl

use strict;
use Net::Jabber qw( Client );
use Digest::SHA1 qw ( sha1_hex );
use Date::Format qw ( time2str );
use Unicode::MapUTF8 qw ( to_utf8 );

use constant SPOOLDIR		=> '/usr/local/jabber/jabber-1.4.1/spool';
use constant ADMINUSERNAME	=> 'youradminname';
use constant ADMINPASSWORD	=> 'youradminpassword';
use constant ADMINSERVER	=> 'youradminserver';
use constant JABBERUID		=> 501;
use constant JABBERGID		=> 501;

my $offices = {
	cologne		=> 'im.example.com',
	dublin		=> 'im.example.com',
	edinburgh	=> 'im.example.com',
	hamburg		=> 'im.example.com',
	leeds		=> 'im.example.com',
	london		=> 'im.example.com',
	madrid		=> 'im.example.com',
	milan		=> 'im.example.com',
	paris		=> 'im.example.com',
	usa		=> 'im.example.com',
};

my( $name, $email, $password, $office );

if( $ARGV[0] ) {
	$name		= $ARGV[0];
	$email		= $ARGV[1];
	$password	= $ARGV[2];
	$office		= $ARGV[3];
} else {
	print "Enter full name: ";
	$name = <STDIN>; chomp $name;

	print "Enter email: ";
	$email = <STDIN>; chomp $email;

	print "Enter password: ";
	$password = <STDIN>; chomp $password;

	print "Enter office: ";
	$office = <STDIN>; chomp $office;

	print "Create $name, $email, $office [Y/N]? ";
	my $ans = <STDIN>;
	if( ! $ans =~ /^[yY]/ ) {
		print "Aborted account creation\n";
		exit;
	}
}

# Munge
( my $name_utf8 = $name ) =~ s/'/&apos;/; # Escape for XML
$name_utf8 = to_utf8(-string => $name, -charset => "ISO-8859-1"); # Change from latin-1 to UTF8, Net::Jabber does this itself
$email = lc( $email );

my $server = $offices->{$office} || die "Unknown office $office";
my ( $username ) = $email =~ /(.*)@(.*)/;

print STDERR "Creating $name, $email ($username:$password)\n";

# Generate password hash
my $time	= time();
my $date	= time2str("%Y%m%dT%T",$time);
my $token	= sprintf( "%X", $time );
my $hash	= sha1_hex(sha1_hex($password) . $token);
my $sequence	= 500; # This is the default seq and will need to be changed if you specify anything other in jabber.xml
my $i		= 0;
while( $i < $sequence ) {
	$hash = sha1_hex($hash);
	$i++;
}

my $xml = <<END_XML;
<xdb><query xmlns='jabber:iq:last' last='$time' xdbns='jabber:iq:last'>Registered</query><zerok xmlns='jabber:iq:auth:0k' xdbns='jabber:iq:auth:0k'><hash>$hash</hash><token>$token</token><sequence>$sequence</sequence></zerok><password xmlns='jabber:iq:auth' xdbns='jabber:iq:auth'>$password</password><query xmlns='jabber:iq:register' xdbns='jabber:iq:register'><name>$name_utf8</name><x xmlns='jabber:x:delay' stamp='$date'>registered</x></query></xdb>
END_XML

print STDERR "Writing $server/$username.xml\n";
open( FH, ">" . SPOOLDIR . "/$server/$username.xml" ) || die "Couldn't open " . SPOOLDIR . "/$server/$username.xml for writing";
	print FH $xml;
close( FH );
chown( JABBERUID, JABBERGID, SPOOLDIR . "/$server/$username.xml" );

# Need to connect to server as user to get jabberd to cache the new and to check it all works of course
my $connect	= new Net::Jabber::Client();
my $conn_resp	= $connect->Connect( hostname => $server );
if ($conn_resp){
	print STDERR "Connected to $server\n";
} else {
	die "Connection failed\n";
}

my @result = $connect->AuthSend(
	username	=> $username,
	password	=> $password,
	resource	=> 'register.pl',
);
if ($result[0] ne "ok") {
	die "Ident/Auth with server failed: $result[0] - $result[1]\n";
} else {
	print STDERR "Authed as $username\n";
}

print STDERR "Adding $username to group '$office'\n";
my $conn_resp = $connect->Connect( hostname => ADMINSERVER );
if ($conn_resp){
	print STDERR "Connected to " . ADMINSERVER . "\n";
} else {
	die "Connection failed\n";
}

my @result = $connect->AuthSend(
	username	=> ADMINUSERNAME,
	password	=> ADMINPASSWORD,
	resource	=> 'register.pl',
);
if ($result[0] ne "ok") {
	die "Ident/Auth with server failed: $result[0] - $result[1]\n";
} else {
	print STDERR "Authed as " . ADMINUSERNAME . "\n";
}

my $iq = new Net::Jabber::IQ();
$iq->SetIQ(
	type	=> 'set',
	to	=> "$server/groups/$office",
	from	=> ADMINUSERNAME . "\@" . ADMINSERVER,
);
my $query = $iq->NewQuery( "jabber:iq:browse" );
$query->AddItem( "user",
	jid	=> "$username\@$server",
	name	=> $name,
);
$connect->Send( $iq );

print STDERR "Added $username to group $server/groups/$office\n";
print STDERR "Done\n\n";
