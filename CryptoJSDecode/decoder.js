// Load CryptoJS library (for Node.js, install with `npm install crypto-js`)
const CryptoJS = require("crypto-js"); // Uncomment if running in Node.js

// Extract `a, b, c, d` from your JSON
const payload = {
    a: "29kRp91YAkl1\/w5cR1+ztEPKY\/8ligsFFN23wSMU8Akz091cx8T6U39RIncmXf8G7kigJvmhMh\/9et5NmHo\/0gz0+npdWpA6bpnlKcnRLmM0Ky03FlPvi6n++TCv3kgjwhTmL8DyYK24PWayllY3p40mvOT\/za7VZN6hnXShOJ1Y25KuPXyqTi\/h+92272v2kYRCru2u8HN7O\/AiHpEI7Z72MaHST\/R9\/OGe3aMQHYcGp2eBH3EZneXFVG1NHVDyxC0pYVsmdk4e1mfPjICcFvd232KVOr7Lcm5bqsgdkgRjY4yRC3i5SsPOsVRbtkBAYEqkxh+QoEXvFYMehIquvN85BtfQZZTTly+PK6+4idToTeerG9eZsuUJN7aG0bgUiKUCZmzZN8nmJCMhu0Mb5Z5amOnKXClQxUesFS1JcTDlU5Riq3VdlOq6G+Qh\/42MZ7y8ZH6uRlzwxa7Uim+Lxz4IfT2RrmzH+UW2e+AnffFGCmkbw1cbVvybDM9xO\/tr8YWeNQ8JNvbi1eAAPH+HsUa7j8bCapXA6sMKuhnCs5oT0SShtfDDasgWDbiDt7AmA15OMOXlv6qdcIka5q8t\/uM253k0+9n4vZIJyad0u8zqNPrgvwGZlo6ceBE3HjwNUQlO4UCIYlKwgPvpPlvlq53B7qdH55jOHtGrKhEST182rM13GUbdwwTfLtjJu+reFSy0FrOxg3myyswmCpFf2\/S0EICaiajkjBeuQVDQw\/H4mFc\/JijMPOcbJhK0a21NduUP59jtAtyKrbeiXD7eyA==",  // Replace with extracted `a`
    b: "c77f0cb6d38593ae3942361a0c5d3060",  // Replace with extracted `b`
    c: "67e6012c128893ce73ed19baa2d8d504",  // Replace with extracted `c`
    d: "6232636133333230643665653933633261623566316532333066383961383932"   // Replace with extracted `d`
};

// Convert hex values to CryptoJS format
const encryptedData = CryptoJS.enc.Base64.parse(payload.a);  // `a` is Base64
const salt = CryptoJS.enc.Hex.parse(payload.b);              // `b` is hex (salt)
const iv = CryptoJS.enc.Hex.parse(payload.c);                // `c` is hex (IV)
const passphrase = CryptoJS.enc.Hex.parse(payload.d);        // `d` is hex (passphrase)

// Derive the AES key using PBKDF2 (SHA-512, 999 iterations)
const key = CryptoJS.PBKDF2(passphrase, salt, {
    hasher: CryptoJS.algo.SHA512,
    keySize: 64 / 8,  // Matches `64 / 8` in your script (AES-256)
    iterations: 999
});

// Decrypt `a` using AES-CBC
const decrypted = CryptoJS.AES.decrypt(
    { ciphertext: encryptedData },
    key,
    { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
);

// Convert decrypted data to a UTF-8 string
let finalPayload = decrypted.toString(CryptoJS.enc.Utf8);

// Perform the replacement (if needed)
finalPayload = finalPayload.replace(/blwRbXUYPJwusSMx/g, "rwUuql");  // Replace the obfuscated string

console.log("Decrypted Payload:", finalPayload);
