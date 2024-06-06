
jQuery.fn.copyText = function(options) {
    var sourceSelector = options.sourceSelector;
    if (typeof sourceSelector !== 'string' || !sourceSelector.match(/^[A-Za-z0-9#_. -]+$/)) {
        console.error('Invalid source selector');
        return;
    }

    var source = jQuery(sourceSelector),
        text = source.text();
    jQuery(this).text(text);
}
