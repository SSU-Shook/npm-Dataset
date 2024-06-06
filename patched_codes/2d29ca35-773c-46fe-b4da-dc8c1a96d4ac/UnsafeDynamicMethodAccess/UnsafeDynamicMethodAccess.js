// API methods
function play(data) {
  // ...
}
function pause(data) {
  // ...
}

window.addEventListener("message", (ev) => {
    let message = JSON.parse(ev.data);

    // Define a list of allowed methods
    const allowedMethods = {
        play: play,
        pause: pause
    };

    // Validate that message.name is an allowed method
    if (message.name in allowedMethods) {
        allowedMethods[message.name](message.payload);
    } else {
        console.error('Attempted to call an undefined method: ' + message.name);
    }
});
