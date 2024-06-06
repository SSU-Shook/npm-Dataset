function merge(dst, src) {
    for (let key in src) {
        if (!src.hasOwnProperty(key)) continue;
        if (isObject(dst[key])) {
            merge(dst[key], src[key]);
        } else {
            dst[key] = src[key]; /*Vulnerability name: Prototype-polluting function	Vulnerability description: Functions recursively assigning properties on objects may be the cause of accidental modification of a built-in prototype object.	Vulnerability message: Properties are copied from [["src"|"relative:///PrototypePollutingFunction.js:2:21:2:23"]] to [["dst"|"relative:///PrototypePollutingFunction.js:7:13:7:15"]] without guarding against prototype pollution.*/
        }
    }
}
