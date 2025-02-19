// auth.js
const authToken = sessionStorage.getItem('AuthToken');
if (!authToken) {
    alert("Please login to access this page.");
    window.location.href = 'index.html';
}
