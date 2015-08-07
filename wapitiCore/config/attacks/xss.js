/*
$ phantomjs <xss.js><html_response_file>
*/
var system = require('system');
var fs = require('fs');
var wp = new WebPage();

wp.settings = {
	loadImages: true,
	localToRemoteUrlAccessEnabled: true,
	javascriptEnabled: true,
	webSecurityEnabled: true,
	XSSAuditingEnabled: true
};

var isXSS = new Object();
isXSS.value = 0;
isXSS.msg = 'Safe';

var html_response_file = system.args[1];
wp.content = fs.read('js-overrides.js') + fs.read(html_response_file);

isXSS.msg = wp.evaluate(function() {
	return xss.message;
});

if(isXSS.msg) {
	console.log(isXSS.msg);
	phantom.exit();
}

phantom.exit();