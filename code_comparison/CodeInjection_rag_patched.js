// Extract the value safely without evaluating the code directly.
const queryParams = new URLSearchParams(window.location.search);
const defaultParam = queryParams.get('default');
console.log(defaultParam); // Handle the parameter safely.
