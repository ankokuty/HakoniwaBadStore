#!perl -w 

### Perl client for search of BadStore.net v2.1 item database ###

use SOAP::Lite;

my $routine=$ARGV[0];
my $squery=$ARGV[1];

if ($routine eq "") {
 print "\nusage:  perl wsdlSearchClient.pl [SearchByNum,SearchByName,SearchByPrice] [search criteria]\n\n";

}else{

print SOAP::Lite
 ->service('http://www.badstore.net/soapSearch.wsdl') 
 ->$routine($squery);
print "\n\n";
}