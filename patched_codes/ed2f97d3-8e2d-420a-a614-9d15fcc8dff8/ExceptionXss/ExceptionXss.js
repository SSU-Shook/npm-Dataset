
function setLanguageOptions() {
    var href = document.location.href,
        deflt = href.substring(href.indexOf("default=")+8);
    
    try {
        var parsed = unknownParseFunction(deflt); 
    } catch(e) {
        var errorText = document.createTextNode("Had an error: " + e + "."); 
        document.body.appendChild(errorText);
    }
}
