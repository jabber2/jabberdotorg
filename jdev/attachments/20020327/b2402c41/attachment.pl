#!/usr/bin/perl

use strict;

use Net::Jabber qw( Client );
use Digest::SHA1 qw( sha1_hex );
use Date::Format qw( time2str );
use Unicode::MapUTF8 qw( to_utf8 );

use constant SPOOLDIR => '/usr/local/jabber/spool';
use constant ADMINUSERNAME => 'admin';
use constant ADMINPASSWORD => 'mypassword';
use constant ADMINSERVER => 'localhost';

my $jabberuid = (getpwnam("jabber"))[2];
my $jabbergid = (getpwnam("jabber"))[3];
my $server = 'jabberq.mycompany.com';
my ($name, $email, $password, $group, $result);
my $i = 0;


if( $ARGV[0] )
{
	$name = $ARGV[0];
	$email = $ARGV[1];
	$password = $ARGV[2];
	$group = $ARGV[3];
}
else
{
	print "Enter full name: ";
	$name = <STDIN>; chomp $name;

	print "Enter email: ";
	$email = <STDIN>; chomp $email;

	print "Enter password: ";
	$password = <STDIN>; chomp $password;

	print "Enter group: ";
	$group = <STDIN>; chomp $group;

	print "Create $name, $email, $group [Y/N]? ";
	my $ans = <STDIN>;
	if( ! $ans =~ /^[yY]/ )
	{
		print "Aborted account creation\n";
		exit;
	}
}

# Munge
( my $name_utf8 = $name ) =~ s/'/&apos;/; # Escape for XML
# Change from latin-1 to UTF8, Net::Jabber does this itself
$name_utf8 = to_utf8(-string => $name, -charset => "ISO-8859-1");
$email = lc( $email );

my ( $username ) = $email =~ /(.*)@(.*)/;

print STDERR "Creating $name, $email ($username:$password)\n";

# Generate password hash
my $time = time();
my $date = time2str("%Y%m%dT%T",$time);
my $token = sprintf( "%X", $time );
my $hash = sha1_hex(sha1_hex($password) . $token);
my $sequence = 500; # This is the default seq and will need to be changed if you specify anything other in jabber.xml
for ($i = 0; $i < $sequence; $i++)
{
	$hash = sha1_hex($hash);
}

my $xml = <<END_XML;
<xdb><query xmlns='jabber:iq:last' last='$time' xdbns='jabber:iq:last'>Registered</query><zerok xmlns='jabber:iq:auth:0k' xdbns='jabber:iq:auth:0k'><hash>$hash</hash><token>$token</token><sequence>$sequence</sequence></zerok><password xmlns='jabber:iq:auth' xdbns='jabber:iq:auth'>$password</password><query xmlns='jabber:iq:register' xdbns='jabber:iq:register'><name>$name_utf8</name><x xmlns='jabber:x:delay' stamp='$date'>registered</x></query></xdb>
END_XML

print STDERR "Writing $server/$username.xml\n";
open( FH, ">" . SPOOLDIR . "/$server/$username.xml" ) || die "Couldn't open " . SPOOLDIR . "/$server/$username.xml for writing";
	print FH $xml;
close( FH );

chown( $jabberuid, $jabbergid, SPOOLDIR . "/$server/$username.xml" );
chmod( 0600, SPOOLDIR . "/$server/$username.xml" );

# Need to connect to server as user to get jabberd to cache the new account
# and to check that it all works
my $client = Net::Jabber::Client->new();
$client->Connect(hostname => $server) || die "Connection failed\n";
print STDERR "Connected to $server\n";

$client->AuthSend( username => $username,
		password => $password,
		resource => 'register.pl');
if ($@)
{
	die "user authentication with server failed: $@\n";
}

print STDERR "Authed as $username\n";

print STDERR "Adding to JUD\n";
my $iq = Net::Jabber::IQ->new();
$iq->SetIQ(type => 'set',
	to => 'jabber-jud.mycompany.com');
my $query = $iq->NewQuery( 'jabber:iq:register' );
$query->SetName($name);
$query->SetEmail($email);
$result = $client->SendAndReceiveWithID($iq);
if ($result->GetType() eq 'result')
{
	print STDERR "Successful registration\n";
}
else
{
	print STDERR "Error: ", $result->GetErrorCode(),
		" (", $result->GetError(), ")\n";
}

# attempt at sending as raw XML...
#$client->Send("<iq type='set' to='localhost'><query xmlns='jabber:iq:register'><name>$name</name><email>$email</email></query></iq>");


print STDERR "Adding $username to group '$group'\n";
$client->Connect( hostname => ADMINSERVER, port => 5222 ) || die "Connection failed\n";
print STDERR "Connected to " . ADMINSERVER . "\n";

$client->AuthSend( username => ADMINUSERNAME,
		password => ADMINPASSWORD,
		resource => 'register.pl');
if ($@)
{
	die "admin authentication with server failed: $@\n";
}
print STDERR "Authed as " . ADMINUSERNAME . "\n";

$iq = Net::Jabber::IQ->new();
$iq->SetIQ( type => 'set',
		to => "$server/groups/$group",
		from => ADMINUSERNAME . "\@" . ADMINSERVER);
$query = $iq->NewQuery( "jabber:iq:browse" );
$query->AddItem( "user",
	jid => "$username\@$server",
	name => $name);
$client->Send( $iq );

print STDERR "Added $username to group $server/groups/$group\n";
print STDERR "Done\n\n";

