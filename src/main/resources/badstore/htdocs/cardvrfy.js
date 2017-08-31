/* Cardvrfy.js - Part of BadStore.net v2.1 */

function DoCardvrfy(x)
{

var card=(x["ccard"].value);
var cexp=(x["expdate"].value);
var validcard= /([0-9]{13,16})/;
var validexpr= /([0-9]{4})/;
var luhn=0;
var isEven=false;
var mastercard= /(5[1-5][0-9]{14})/;
var visacard= /(4[0-9]{15})/;
var amexcard= /(3(4|7)[0-9]{13})/;
var discovercard= /(6011[0-9]{12})/;
var jcb= /((3|2131|1800)[0-9]{11,15})/;

// Check for input
if ((card == '') || (cexp == ''))  {
	alert("You haven't entered enough information!");
 	return false; 
}

// Ensure only numbers

if (!validcard.exec(card)) {
	alert("Only valid numbers are allowed - and no spaces or dashes!");
	return false; 
}

for (n=card.length-1; n>=0; n--)
{
	var y=card.charAt(n);
	var z=parseInt(y,10);
	if (isEven)
	{
	 if ((z*=2)>9)
	 z -=9;
	}
	luhn +=z;
	isEven = ! isEven;
}
if ((luhn % 10) != 0) {
	alert("Bad Card Number: Invalid Luhn Checksum");
	return false;
}

// Check for a MasterCard
if (mastercard.test(card)) {
	alert("Thank you for using MasterCard!");
	return true;
}

// Check for Visa
if (visacard.exec(card)) {
	alert("Thank you for using Visa!");
	return true;
}

// Check for American Express
if (amexcard.exec(card)) {
	alert("Thank you for using American Express!");
	return true;
}

// Check for Discover
if (discovercard.exec(card)) {
	alert("Thank you for using Discover!");
	return true;
}

// Check for JCB
if (jcb.exec(card)) {
	alert("Thank you for using JCB!");
	return true;
}

// Unknown credit card type
alert("You have entered an unaccepted card - please use a supported method of payment");
return false;
}

