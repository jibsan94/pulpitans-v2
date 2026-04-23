/**
 * auth.js — Shared authentication helper for Pulpitans.
 *
 * Reads/writes a persistent cookie "pulpitans_user" with the logged-in username.
 * Every protected page should call PulpitansAuth.requireLogin() on load.
 */
const PulpitansAuth = (function () {
    const COOKIE_NAME = 'pulpitans_user';
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
    function login(username) {
        setCookie(COOKIE_NAME, username, COOKIE_DAYS);
    }

    /** Clears auth cookie and redirects to login page. */
    function logout() {
        deleteCookie(COOKIE_NAME);
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
        try {
            const API_BASE = window.PULPITANS_API_BASE || window.API_BASE || '/api';
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
        } catch (e) {
            // Silently fall back to username
            const nameEl = document.getElementById('header-user-display-name');
            if (nameEl) nameEl.textContent = username;
        }
    }

    /** Convenience: get display name synchronously from cache or fallback to username. */
    function getDisplayName() {
        const nameEl = document.getElementById('header-user-display-name');
        return (nameEl && nameEl.textContent) || getUsername() || 'Unknown';
    }

    return {
        getUsername,
        getDisplayName,
        login,
        logout,
        requireLogin
    };
})();
