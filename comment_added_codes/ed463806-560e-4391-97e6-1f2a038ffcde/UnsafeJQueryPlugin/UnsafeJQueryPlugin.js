jQuery.fn.copyText = function(options) {
	// BAD may evaluate `options.sourceSelector` as HTML
	var source = jQuery(options.sourceSelector), /*Vulnerability name: Unsafe jQuery plugin	Vulnerability description: A jQuery plugin that unintentionally constructs HTML from some of its options may be unsafe to use for clients.	Vulnerability message: Potential XSS vulnerability in the [["'$.fn.copyText' plugin"|"relative:///UnsafeJQueryPlugin.js:1:22:6:1"]].*/
	    text = source.text();
	jQuery(this).text(text);
}
