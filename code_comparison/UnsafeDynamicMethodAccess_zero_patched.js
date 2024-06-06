// API methods
function play(data) {
  // ...
}
function pause(data) {
  // ...
}

// List of allowed methods
const allowedMethods = {
  play,
  pause
};

window.addEventListener("message", (ev) => {
    let message = JSON.parse(ev.data);

    // Ensure the method name is allowed
    if (allowedMethods.hasOwnProperty(message.name)) {
        allowedMethods[message.name](message.payload);
    } else {
        console.error("Invalid method name");
    }
});
