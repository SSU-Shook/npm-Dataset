
function setLanguageOptions() {
    var href = document.location.href,
        deflt = href.substring(href.indexOf("default=")+8);
    // Create a text node to safely insert the user-provided value
    var selectElement = document.createElement("select");
    var optionElement = document.createElement("option");
    optionElement.value = '1';
    optionElement.textContent = deflt;  // Secure method to set the text content
    selectElement.appendChild(optionElement);
    document.body.appendChild(selectElement);

    // Existing option
    document.write("<OPTION value=2>English</OPTION>");
}
