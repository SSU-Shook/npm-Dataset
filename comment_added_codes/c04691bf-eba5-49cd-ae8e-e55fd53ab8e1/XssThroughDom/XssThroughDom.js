$("button").click(function () {
    var target = $(this).attr("data-target");
    $(target).hide(); /*Vulnerability name: DOM text reinterpreted as HTML	Vulnerability description: Reinterpreting text from the DOM as HTML can lead to a cross-site scripting vulnerability.	Vulnerability message: [["DOM text"|"relative:///XssThroughDom.js:2:18:2:44"]] is reinterpreted as HTML without escaping meta-characters.*/
});
