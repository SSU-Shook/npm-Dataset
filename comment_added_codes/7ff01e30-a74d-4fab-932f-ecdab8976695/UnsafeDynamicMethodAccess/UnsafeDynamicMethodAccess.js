// API methods
function play(data) {
  // ...
}
function pause(data) {
  // ...
}

window.addEventListener("message", (ev) => {
    let message = JSON.parse(ev.data);

    // Let the parent frame call the 'play' or 'pause' function 
    window[message.name](message.payload); /*Vulnerability name: Unsafe dynamic method access	Vulnerability description: Invoking user-controlled methods on certain objects can lead to remote code execution.	Vulnerability message: This method is invoked using a [["user-controlled value"|"relative:///UnsafeDynamicMethodAccess.js:9:37:9:38"]], which may allow remote code execution.*/
});
