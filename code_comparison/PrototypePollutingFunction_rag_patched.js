
function merge(dst, src) {
    for (let key in src) {
        if (!src.hasOwnProperty(key)) continue;
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue; // Prevent prototype pollution
        if (isObject(dst[key])) {
            merge(dst[key], src[key]);
        } else {
            dst[key] = src[key];
        }
    }
}
