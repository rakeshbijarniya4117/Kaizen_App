// auth.js
const LOGIN_PAGE = 'login.html';
const HOME_PAGE  = 'index.html';   // change to your real home page name

// ⚠️ DEV BYPASS: set to false before production
const DEV_BYPASS = true;
const DEV_EMP_ID = 'LOCAL_DEV_999'; // must match DEV_EMP_ID in .env (a real ID if you want to save Kaizens)

if (DEV_BYPASS) {
    // Fake but well-formed token (far-future exp) so isTokenExpired() passes.
    // The server ignores it while DISABLE_AUTH=true.
    const fakePayload = btoa(JSON.stringify({ emp_id: DEV_EMP_ID, exp: 4102444800 }));
    localStorage.setItem('jwt_token', `dev.${fakePayload}.dev`);
    localStorage.setItem('currentUser', JSON.stringify({
        emp_id: DEV_EMP_ID, fname: 'Local', lname: 'Developer', email: 'local.dev@example.com',
        is_admin: true, is_hod: true, is_committee: true, is_coordinator: true, is_hok: true
    }));
    // If we land on the login page, skip it
    const p = window.location.pathname.split('/').pop();
    if (p === LOGIN_PAGE) window.location.replace(HOME_PAGE);
}

function destroySession() {
    if (DEV_BYPASS) return;            // never log out in dev mode
    localStorage.removeItem('jwt_token');
    localStorage.removeItem('currentUser');
    const currentPage = window.location.pathname.split("/").pop();
    if (currentPage !== LOGIN_PAGE && currentPage !== '') {
        window.location.replace(LOGIN_PAGE);
    }
}