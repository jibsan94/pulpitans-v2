/**
 * auth.js — Shared authentication helper for Pulpitans.
 *
 * Reads/writes a persistent cookie "pulpitans_user" with the logged-in username.
 * Every protected page should call PulpitansAuth.requireLogin() on load.
 */
const PulpitansAuth = (function () {
    const COOKIE_NAME = 'pulpitans_user';
    const PAM_COOKIE  = 'pulpitans_pam';
    const COOKIE_DAYS = 365;

    /* ---------- Cookie helpers ---------- */

    function setCookie(name, value, days) {
        let expires = '';
        if (days) {
            const d = new Date();
            d.setTime(d.getTime() + days * 86400000);
            expires = '; expires=' + d.toUTCString();
        }
        document.cookie = name + '=' + encodeURIComponent(value) + expires + '; path=/; SameSite=Lax';
    }

    function getCookie(name) {
        const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
        return match ? decodeURIComponent(match[1]) : null;
    }

    function deleteCookie(name) {
        document.cookie = name + '=; Max-Age=0; path=/; SameSite=Lax';
    }

    /* ---------- Public API ---------- */

    /** Returns the current username from cookie, or null. */
    function getUsername() {
        return getCookie(COOKIE_NAME) || null;
    }

    /** Stores the username in a persistent cookie. */
    function login(username, pamValid) {
        setCookie(COOKIE_NAME, username, COOKIE_DAYS);
        setCookie(PAM_COOKIE, pamValid ? '1' : '0', COOKIE_DAYS);
    }

    /** Returns true if the user's password matched PAM at login. */
    function isPamValid() {
        return getCookie(PAM_COOKIE) === '1';
    }

    /** Clears auth cookie and redirects to login page. */
    function logout() {
        deleteCookie(COOKIE_NAME);
        deleteCookie(PAM_COOKIE);
        window.location.href = 'authentication-login1.html';
    }

    /**
     * Call on page load of every protected page.
     * If no cookie → redirect to login.
     * Otherwise returns the username and injects display name into the header.
     */
    function requireLogin() {
        const user = getUsername();
        if (!user) {
            window.location.href = 'authentication-login1.html';
            return null;
        }
        // Load display name and populate header
        _loadHeaderProfile(user);
        return user;
    }

    /**
     * Fetches display name from backend and updates the header user dropdown.
     */
    async function _loadHeaderProfile(username) {
        const API_BASE = window.PULPITANS_API_BASE || window.API_BASE || '/api';
        // Always set profile picture (even if profile fetch fails)
        const picUrl = `${API_BASE}/auth/profile-picture/${encodeURIComponent(username)}?t=${Date.now()}`;
        document.querySelectorAll('.user-profile-pic').forEach(img => {
            img.src = picUrl;
        });
        try {
            const res = await fetch(`${API_BASE}/auth/profile?username=${encodeURIComponent(username)}`);
            const data = await res.json();
            const displayName = (data.success && data.profile.display_name) ? data.profile.display_name : username;

            // Update header elements
            const nameEl = document.getElementById('header-user-display-name');
            if (nameEl) nameEl.textContent = displayName;

            const profileNameEl = document.getElementById('profile-modal-username');
            if (profileNameEl) profileNameEl.textContent = username;

            // Check admin status and show admin menu items
            if (data.success && data.profile.is_admin) {
                document.querySelectorAll('.admin-only').forEach(el => el.style.display = '');
                if (typeof feather !== 'undefined') feather.replace();
            }

            // Show PAM warning banner if credentials don't match the local server
            if (!isPamValid()) {
                _showPamBanner();
            }
        } catch (e) {
            console.warn('[auth.js] _loadHeaderProfile error:', e);
            const nameEl = document.getElementById('header-user-display-name');
            if (nameEl) nameEl.textContent = username;
        }
    }

    /** Convenience: get display name synchronously from cache or fallback to username. */
    function getDisplayName() {
        const nameEl = document.getElementById('header-user-display-name');
        return (nameEl && nameEl.textContent) || getUsername() || 'Unknown';
    }

    /** Shows a warning banner when PAM credentials don't match the local server. */
    function _showPamBanner() {
        if (document.getElementById('pam-warning-banner')) return;
        const pageWrapper = document.querySelector('.page-wrapper');
        if (!pageWrapper) return;
        const banner = document.createElement('div');
        banner.id = 'pam-warning-banner';
        banner.className = 'alert alert-warning alert-dismissible fade show mb-0 rounded-0 border-start-0 border-end-0';
        banner.setAttribute('role', 'alert');
        banner.style.cssText = 'position:relative;z-index:100;';
        banner.innerHTML =
            '<div class="d-flex align-items-center">' +
                '<i data-feather="alert-triangle" class="feather-sm me-2 flex-shrink-0"></i>' +
                '<span><strong>Credentials mismatch:</strong> Your password does not match the local server. ' +
                'Some features (e.g. deleting builds) will not work. Please update your password in ' +
                '<a href="my-profile.html" class="alert-link">My Profile</a> to match your server credentials.</span>' +
                '<button type="button" class="btn-close ms-auto" data-bs-dismiss="alert" aria-label="Close"></button>' +
            '</div>';
        pageWrapper.insertBefore(banner, pageWrapper.firstChild);
        if (typeof feather !== 'undefined') feather.replace();
    }

    return {
        getUsername,
        getDisplayName,
        isPamValid,
        login,
        logout,
        requireLogin
    };
})();
