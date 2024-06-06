function setLanguageOptions() {
    var href = document.location.href,
        deflt = href.substring(href.indexOf("default=")+8);

    // Sanitize the user input before writing to the DOM
    deflt = sanitizeInput(deflt);

    document.write("<OPTION value=1>"+deflt+"</OPTION>");
    document.write("<OPTION value=2>English</OPTION>");
}

function sanitizeInput(input) {
    var element = document.createElement('div');
    element.innerText = input;
    return element.innerHTML;
}
