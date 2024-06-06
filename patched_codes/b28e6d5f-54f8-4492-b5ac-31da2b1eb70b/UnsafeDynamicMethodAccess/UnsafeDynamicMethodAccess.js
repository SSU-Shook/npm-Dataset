// API methods
function play(data) {
  // ...
}
function pause(data) {
  // ...
}

window.addEventListener("message", (ev) => {
    let message = JSON.parse(ev.data);

    // Allow only 'play' or 'pause'
    const allowedMethods = ['play', 'pause'];
    if (allowedMethods.includes(message.name)) {
        window[message.name](message.payload);
    } else {
        console.error(`Method ${message.name} is not allowed.`);
    }
});
