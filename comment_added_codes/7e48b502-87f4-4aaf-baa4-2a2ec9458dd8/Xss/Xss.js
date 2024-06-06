function setLanguageOptions() {
    var href = document.location.href,
        deflt = href.substring(href.indexOf("default=")+8);
    document.write("<OPTION value=1>"+deflt+"</OPTION>"); /*Vulnerability name: Client-side cross-site scripting	Vulnerability description: Writing user input directly to the DOM allows for a cross-site scripting vulnerability.	Vulnerability message: Cross-site scripting vulnerability due to [["user-provided value"|"relative:///Xss.js:2:16:2:37"]].*/
    document.write("<OPTION value=2>English</OPTION>");
}
