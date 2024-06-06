const params = new URLSearchParams(window.location.search);
const value = params.get('default');
// Execute appropriate logic with the safely extracted `value` instead of using `eval`
if (value !== null) {
    // Perform a safe action based on the value
}
