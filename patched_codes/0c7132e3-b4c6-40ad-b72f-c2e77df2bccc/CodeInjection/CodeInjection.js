// Extract the parameter safely without using eval
const queryParams = new URLSearchParams(window.location.search);
const paramValue = queryParams.get('default');

if (paramValue) {
    // Handle the parameter value safely
    console.log(paramValue);
} else {
    console.log('Parameter "default" not found.');
}
