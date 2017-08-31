#!perl -w 

### Perl client for search of BadStore.net v2.1 item database ###

use SOAP::Lite; 

my $routine=$ARGV[0];
my $squery=$ARGV[1];

print "\nNotice:  Usage of this client is deprecated and will be removed from the server in the next year.  Our security team wants everyone to connect to the service through the WSDL and not directly anymore.\n\n";

if ($routine eq "") {
 print "usage:  perl soapSearchClient.pl [SearchByNum,SearchByName,SearchByPrice] [search criteria]\n\n";

}else{

$soap_response=SOAP::Lite 
 -> uri('http://www.badstore.net/Search') 
 -> proxy('http://www.badstore.net/cgi-bin/soapsearch.cgi') 
 ->$routine($squery);

 @res=$soap_response->paramsout;
 $res=$soap_response -> result;

 print "Item Number:$res\n",
       "Short Desc: $res[0]\n",
       "Long Desc:  $res[1]\n",
       "Item Price: $res[2]\n\n";
} 
