jQuery.fn.copyText = function(options) {
    // Safely fetch the source element
    var source = jQuery(options.sourceSelector); // Ensure the selector is valid and safe

    // Get the text content of the source element
    var text = source.text();

    // Set the text of the target element to the text from the source
    jQuery(this).text(text);
}
