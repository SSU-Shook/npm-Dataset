
// API methods
function play(data) {
  // ...
}

function pause(data) {
  // ...
}

// List of allowed methods
const allowedMethods = {
  play: play,
  pause: pause
};

window.addEventListener("message", (ev) => {
    let message = JSON.parse(ev.data);

    // Let the parent frame call the 'play' or 'pause' function 
    if (allowedMethods[message.name]) {
        allowedMethods[message.name](message.payload);
    } else {
        console.error("Attempt to call an invalid method:", message.name);
    }
});
