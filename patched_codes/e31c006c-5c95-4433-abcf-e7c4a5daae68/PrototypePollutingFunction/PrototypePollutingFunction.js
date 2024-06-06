
function merge(dst, src) {
    const unsafeKeys = ['__proto__', 'constructor', 'prototype']; // List of unsafe keys
    for (let key in src) {
        if (!src.hasOwnProperty(key)) continue;

        // Check if key is one of the unsafe keys
        if (unsafeKeys.includes(key)) continue;

        if (isObject(dst[key])) {
            merge(dst[key], src[key]);
        } else {
            dst[key] = src[key];
        }
    }
}
