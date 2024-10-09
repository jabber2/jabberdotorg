
<!-- sending@2016-06-13T19:00:43Z: -->
<?xml version='1.0'?><stream:stream to='chat.facebook.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>

<!-- receive@2016-06-13T19:00:44Z: -->
<stream:stream from="chat.facebook.com" id="1" version="1.0" xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" xml:lang="en"/>
<!-- receive@2016-06-13T19:00:44Z: -->
<stream:features>
  <starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>
  <mechanisms xmlns="urn:ietf:params:xml:ns:xmpp-sasl">
    <mechanism>X-FACEBOOK-PLATFORM</mechanism>
    <mechanism>PLAIN</mechanism>
  </mechanisms>
</stream:features>
<!-- sending@2016-06-13T19:00:44Z: -->
<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>
<!-- receive@2016-06-13T19:00:44Z: -->
<proceed xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>
<!-- sending@2016-06-13T19:00:44Z: -->
<?xml version='1.0'?><stream:stream to='chat.facebook.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>

<!-- receive@2016-06-13T19:00:44Z: -->
<stream:stream from="chat.facebook.com" id="1" version="1.0" xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" xml:lang="en"/>
<!-- receive@2016-06-13T19:00:44Z: -->
<stream:features>
  <mechanisms xmlns="urn:ietf:params:xml:ns:xmpp-sasl">
    <mechanism>X-FACEBOOK-PLATFORM</mechanism>
    <mechanism>PLAIN</mechanism>
  </mechanisms>
</stream:features>
<!-- sending@2016-06-13T19:00:48Z: -->
<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="PLAIN">xxx</auth>
<!-- receive@2016-06-13T19:00:48Z: -->
<failure xmlns="urn:ietf:params:xml:ns:xmpp-sasl">
  <not-authorized/>
  <text>plain login failed</text>
</failure>
<!-- + -->
