/* OIDC PKCE client for the SOC UI. Access tokens are session-scoped; no refresh token is retained. */
(() => {
    "use strict";
    const API_BASE = String(window.MAILTRACE_API_BASE || "http://127.0.0.1:8002").replace(/\/+$/, "");
    let accessToken = "";
    let accessTokenExpiry = 0;
    const STATE_KEY = "mailtrace_oidc_state";
    const VERIFIER_KEY = "mailtrace_oidc_pkce_verifier";
    const nativeFetch = window.fetch.bind(window);
    let config = null;
    let principal = null;
    let authError = "";
    let readyResolve;
    const authReady = new Promise(resolve => { readyResolve = resolve; });

    function getToken() {
        if (!accessToken || (accessTokenExpiry && Date.now() >= accessTokenExpiry)) {
            accessToken = "";
            accessTokenExpiry = 0;
            return "";
        }
        return accessToken;
    }

    function b64url(bytes) {
        let binary = "";
        bytes.forEach(byte => { binary += String.fromCharCode(byte); });
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    function randomValue(size = 32) {
        const bytes = new Uint8Array(size);
        crypto.getRandomValues(bytes);
        return b64url(bytes);
    }

    function mountButton() {
        if ((!config || !config.enabled) && !authError) return;
        const host = document.querySelector(".topbar-right") || document.querySelector(".topbar");
        if (!host || document.getElementById("mailtraceAuthButton")) return;
        const button = document.createElement("button");
        button.id = "mailtraceAuthButton";
        button.type = "button";
        button.className = "mailtrace-auth-button";
        button.setAttribute("aria-live", "polite");
        button.addEventListener("click", async () => {
            if (!config || !config.enabled) {
                button.title = authError || "Configure the OIDC public client to enable SSO.";
                return;
            }
            if (getToken()) {
                accessToken = "";
                accessTokenExpiry = 0;
                principal = null;
                window.dispatchEvent(new CustomEvent("mailtrace-auth-changed", { detail: { signedIn: false } }));
                updateButton();
                window.location.reload();
                return;
            }
            try {
                const verifier = randomValue(48);
                const challengeBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
                const state = randomValue(32);
                sessionStorage.setItem(STATE_KEY, state);
                sessionStorage.setItem(VERIFIER_KEY, verifier);
                const url = new URL(config.authorization_endpoint);
                url.searchParams.set("response_type", "code");
                url.searchParams.set("client_id", config.client_id);
                url.searchParams.set("redirect_uri", config.redirect_uri);
                url.searchParams.set("scope", config.scopes || "openid profile email");
                url.searchParams.set("state", state);
                url.searchParams.set("code_challenge", b64url(challengeBytes));
                url.searchParams.set("code_challenge_method", "S256");
                window.location.assign(url.toString());
            } catch (error) {
                authError = error.message || "Unable to start SSO sign-in.";
                updateButton();
            }
        });
        host.appendChild(button);
        updateButton();
    }

    function updateButton() {
        const button = document.getElementById("mailtraceAuthButton");
        if (!button) return;
        if (!config || !config.enabled) {
            button.textContent = "SSO unavailable";
            button.disabled = true;
            button.title = authError || "OIDC client settings are not configured by the administrator.";
            button.setAttribute("aria-label", "Single sign-on is not configured");
            return;
        }
        button.disabled = false;
        button.textContent = getToken() ? "Sign out" : "Sign in with SSO";
        button.title = getToken() ? "End this browser-tab session" : "Sign in using your organization's identity provider";
        button.setAttribute("aria-label", button.textContent);
    }

    async function finishCallback() {
        const url = new URL(window.location.href);
        const providerError = url.searchParams.get("error");
        if (providerError) throw new Error(`SSO sign-in failed: ${providerError}`);
        const code = url.searchParams.get("code");
        if (!code) return;
        const returnedState = url.searchParams.get("state") || "";
        const expectedState = sessionStorage.getItem(STATE_KEY) || "";
        const verifier = sessionStorage.getItem(VERIFIER_KEY) || "";
        sessionStorage.removeItem(STATE_KEY);
        sessionStorage.removeItem(VERIFIER_KEY);
        if (!expectedState || returnedState !== expectedState || !verifier) {
            throw new Error("SSO state validation failed. Please sign in again.");
        }
        if (!config || !config.enabled) throw new Error("OIDC client settings are unavailable.");
        const form = new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: config.redirect_uri,
            client_id: config.client_id,
            code_verifier: verifier
        });
        const response = await nativeFetch(config.token_endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: form.toString(),
            cache: "no-store"
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok || !result.access_token) {
            throw new Error("SSO token exchange failed. Check provider redirect URI and SPA CORS settings.");
        }
        // Keep the bearer token in memory only; never persist it in localStorage/sessionStorage.
        accessToken = result.access_token;
        accessTokenExpiry = Date.now() + Math.max(30, Number(result.expires_in || 300)) * 1000;
        url.searchParams.delete("code");
        url.searchParams.delete("state");
        url.searchParams.delete("session_state");
        url.searchParams.delete("iss");
        history.replaceState({}, document.title, url.pathname + url.search + url.hash);
        window.dispatchEvent(new CustomEvent("mailtrace-auth-changed", { detail: { signedIn: true } }));
    }

    // All API calls inherit the same verified access token. External library calls are untouched.
    window.fetch = async function(input, init = {}) {
        let originalUrl;
        try { originalUrl = new URL(typeof input === "string" ? input : input.url, window.location.href); }
        catch (_) { return nativeFetch(input, init); }
        const apiOrigin = new URL(API_BASE, window.location.href).origin;
        const legacyLocalApi = originalUrl.hostname === "127.0.0.1" && originalUrl.port === "8000";
        if (originalUrl.origin !== apiOrigin && !legacyLocalApi) return nativeFetch(input, init);
        await authReady;
        const headers = new Headers(input instanceof Request ? input.headers : undefined);
        new Headers(init.headers || {}).forEach((value, key) => headers.set(key, value));
        const token = getToken();
        if (token && !headers.has("Authorization")) headers.set("Authorization", `Bearer ${token}`);
        const method = String(init.method || (input instanceof Request ? input.method : "GET")).toUpperCase();
        if (method === "POST" && /\/api\/cases\/[^/]+\/(claim|renew|release)(\?|$)/.test(originalUrl.pathname + originalUrl.search) && !headers.has("Idempotency-Key")) {
            headers.set("Idempotency-Key", crypto.randomUUID ? crypto.randomUUID() : randomValue(24));
        }
        const requestUrl = legacyLocalApi && originalUrl.origin !== apiOrigin
            ? new URL(originalUrl.pathname + originalUrl.search + originalUrl.hash, API_BASE).toString()
            : originalUrl.toString();
        const response = await nativeFetch(requestUrl, { ...init, headers });
        if (response.status === 401 && token) {
            accessToken = "";
            accessTokenExpiry = 0;
            principal = null;
            updateButton();
        }
        return response;
    };

    window.mailtraceAuth = {
        getToken,
        getConfig: () => config ? { ...config } : null,
        getPrincipal: () => principal ? { ...principal, roles: [...(principal.roles || [])] } : null,
        hasRole: roles => {
            const required = new Set(Array.isArray(roles) ? roles : [roles]);
            return Boolean(principal && (principal.roles || []).some(role => required.has(role)));
        },
        isSignedIn: () => Boolean(getToken()),
        ready: authReady
    };

    (async () => {
        try {
            const response = await nativeFetch(`${API_BASE}/api/auth/config`, { cache: "no-store" });
            config = response.ok ? await response.json() : { enabled: false };
            await finishCallback();
            try {
                const identityHeaders = new Headers();
                if (getToken()) identityHeaders.set("Authorization", `Bearer ${getToken()}`);
                const identityResponse = await nativeFetch(`${API_BASE}/api/auth/me`, {
                    headers: identityHeaders,
                    cache: "no-store"
                });
                principal = identityResponse.ok ? await identityResponse.json() : null;
            } catch (_) { principal = null; }
        } catch (error) {
            authError = error.message || "Unable to initialize SSO.";
        } finally {
            mountButton();
            updateButton();
            readyResolve();
        }
    })();
})();
