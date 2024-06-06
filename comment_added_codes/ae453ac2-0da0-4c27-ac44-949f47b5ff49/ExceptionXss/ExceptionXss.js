function setLanguageOptions() {
    var href = document.location.href,
        deflt = href.substring(href.indexOf("default=")+8);
    
    try {
        var parsed = unknownParseFunction(deflt); 
    } catch(e) {
        document.write("Had an error: " + e + "."); /*Vulnerability name: Exception text reinterpreted as HTML	Vulnerability description: Reinterpreting text from an exception as HTML can lead to a cross-site scripting vulnerability.	Vulnerability message: [["Exception text"|"relative:///ExceptionXss.js:2:16:2:37"]] is reinterpreted as HTML without escaping meta-characters.*/
    }
}
