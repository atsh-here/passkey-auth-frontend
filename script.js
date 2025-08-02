// Configuration
const CONFIG = {
    // For local development
    API_BASE: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
        ? 'http://localhost:3000/api' 
        : 'https://passkey-auth-backend.onrender.com/api', // Replace with your Render backend URL

    // For GitHub Pages deployment, you'll need to update this URL
    // Example: 'https://your-backend-name.onrender.com/api'
};

class PasskeyAuth {
    constructor() {
        this.init();
    }

    init() {
        // Check if WebAuthn is supported
        if (!window.PublicKeyCredential) {
            this.showMessage('WebAuthn is not supported in this browser', 'error');
            return;
        }

        this.bindEvents();
        this.checkAuthStatus();
    }

    bindEvents() {
        // Form submissions
        document.getElementById('registration-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.register();
        });

        document.getElementById('login-form-element').addEventListener('submit', (e) => {
            e.preventDefault();
            this.authenticate();
        });

        // Authentication without username
        document.getElementById('authenticate-without-username').addEventListener('click', () => {
            this.authenticateWithoutUsername();
        });

        // Form toggles
        document.getElementById('show-register').addEventListener('click', () => {
            this.showForm('register');
        });

        document.getElementById('show-login').addEventListener('click', () => {
            this.showForm('login');
        });

        // Logout
        document.getElementById('logout-btn').addEventListener('click', () => {
            this.logout();
        });
    }

    showForm(formType) {
        const registerForm = document.getElementById('register-form');
        const loginForm = document.getElementById('login-form');
        const showRegisterBtn = document.getElementById('show-register');
        const showLoginBtn = document.getElementById('show-login');

        if (formType === 'register') {
            registerForm.classList.add('active');
            loginForm.classList.remove('active');
            showRegisterBtn.classList.add('active');
            showLoginBtn.classList.remove('active');
        } else {
            registerForm.classList.remove('active');
            loginForm.classList.add('active');
            showRegisterBtn.classList.remove('active');
            showLoginBtn.classList.add('active');
        }

        this.clearMessage();
    }

    async register() {
        const username = document.getElementById('register-username').value;
        const email = document.getElementById('register-email').value;
        const displayName = document.getElementById('register-displayname').value;

        if (!username || !email || !displayName) {
            this.showMessage('Please fill in all fields', 'error');
            return;
        }

        try {
            this.showMessage('Starting registration...', 'info');

            // Get registration options from server
            const optionsResponse = await fetch(`${CONFIG.API_BASE}/register/begin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, displayName })
            });

            if (!optionsResponse.ok) {
                const errorData = await optionsResponse.json();
                throw new Error(errorData.error || 'Failed to start registration');
            }

            const options = await optionsResponse.json();

            // Convert base64url to ArrayBuffer for challenge and user.id
            options.challenge = this.base64urlToArrayBuffer(options.challenge);
            options.user.id = this.base64urlToArrayBuffer(options.user.id);

            // Create credentials
            this.showMessage('Please use your authenticator...', 'info');
            const credential = await navigator.credentials.create({ publicKey: options });

            // Prepare credential data for server
            const credentialData = {
                id: credential.id,
                rawId: this.arrayBufferToBase64url(credential.rawId),
                response: {
                    clientDataJSON: this.arrayBufferToBase64url(credential.response.clientDataJSON),
                    attestationObject: this.arrayBufferToBase64url(credential.response.attestationObject)
                },
                type: credential.type
            };

            // Send credential to server
            const verifyResponse = await fetch(`${CONFIG.API_BASE}/register/complete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username,
                    credential: credentialData
                })
            });

            if (!verifyResponse.ok) {
                const errorData = await verifyResponse.json();
                throw new Error(errorData.error || 'Registration verification failed');
            }

            const result = await verifyResponse.json();
            this.showMessage('Registration successful! You can now sign in.', 'success');

            // Store user session
            localStorage.setItem('userSession', JSON.stringify(result.user));

            // Switch to login form after short delay
            setTimeout(() => {
                this.showForm('login');
            }, 2000);

        } catch (error) {
            console.error('Registration error:', error);
            this.showMessage(`Registration failed: ${error.message}`, 'error');
        }
    }

    async authenticate() {
        const username = document.getElementById('login-username').value;

        if (!username) {
            this.showMessage('Please enter your username', 'error');
            return;
        }

        try {
            this.showMessage('Starting authentication...', 'info');

            // Get authentication options from server
            const optionsResponse = await fetch(`${CONFIG.API_BASE}/authenticate/begin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username })
            });

            if (!optionsResponse.ok) {
                const errorData = await optionsResponse.json();
                throw new Error(errorData.error || 'Failed to start authentication');
            }

            const options = await optionsResponse.json();

            // Convert base64url to ArrayBuffer
            options.challenge = this.base64urlToArrayBuffer(options.challenge);

            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(cred => ({
                    ...cred,
                    id: this.base64urlToArrayBuffer(cred.id)
                }));
            }

            // Get assertion
            this.showMessage('Please use your authenticator...', 'info');
            const assertion = await navigator.credentials.get({ publicKey: options });

            // Prepare assertion data for server
            const assertionData = {
                id: assertion.id,
                rawId: this.arrayBufferToBase64url(assertion.rawId),
                response: {
                    clientDataJSON: this.arrayBufferToBase64url(assertion.response.clientDataJSON),
                    authenticatorData: this.arrayBufferToBase64url(assertion.response.authenticatorData),
                    signature: this.arrayBufferToBase64url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? this.arrayBufferToBase64url(assertion.response.userHandle) : null
                },
                type: assertion.type
            };

            // Send assertion to server
            const verifyResponse = await fetch(`${CONFIG.API_BASE}/authenticate/complete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username,
                    assertion: assertionData
                })
            });

            if (!verifyResponse.ok) {
                const errorData = await verifyResponse.json();
                throw new Error(errorData.error || 'Authentication verification failed');
            }

            const result = await verifyResponse.json();
            this.showMessage('Authentication successful!', 'success');

            // Store user session and show profile
            localStorage.setItem('userSession', JSON.stringify(result.user));
            this.showProfile(result.user);

        } catch (error) {
            console.error('Authentication error:', error);
            this.showMessage(`Authentication failed: ${error.message}`, 'error');
        }
    }

    async authenticateWithoutUsername() {
        try {
            this.showMessage('Starting authentication...', 'info');

            // Get authentication options from server (without username)
            const optionsResponse = await fetch(`${CONFIG.API_BASE}/authenticate/begin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });

            if (!optionsResponse.ok) {
                const errorData = await optionsResponse.json();
                throw new Error(errorData.error || 'Failed to start authentication');
            }

            const options = await optionsResponse.json();

            // Convert base64url to ArrayBuffer
            options.challenge = this.base64urlToArrayBuffer(options.challenge);

            // Get assertion
            this.showMessage('Please use your authenticator...', 'info');
            const assertion = await navigator.credentials.get({ publicKey: options });

            // Prepare assertion data for server
            const assertionData = {
                id: assertion.id,
                rawId: this.arrayBufferToBase64url(assertion.rawId),
                response: {
                    clientDataJSON: this.arrayBufferToBase64url(assertion.response.clientDataJSON),
                    authenticatorData: this.arrayBufferToBase64url(assertion.response.authenticatorData),
                    signature: this.arrayBufferToBase64url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? this.arrayBufferToBase64url(assertion.response.userHandle) : null
                },
                type: assertion.type
            };

            // Send assertion to server
            const verifyResponse = await fetch(`${CONFIG.API_BASE}/authenticate/complete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    assertion: assertionData
                })
            });

            if (!verifyResponse.ok) {
                const errorData = await verifyResponse.json();
                throw new Error(errorData.error || 'Authentication verification failed');
            }

            const result = await verifyResponse.json();
            this.showMessage('Authentication successful!', 'success');

            // Store user session and show profile
            localStorage.setItem('userSession', JSON.stringify(result.user));
            this.showProfile(result.user);

        } catch (error) {
            console.error('Authentication error:', error);
            this.showMessage(`Authentication failed: ${error.message}`, 'error');
        }
    }

    showProfile(user) {
        const profileSection = document.getElementById('profile-section');
        const registerForm = document.getElementById('register-form');
        const loginForm = document.getElementById('login-form');
        const userInfo = document.getElementById('user-info');

        // Hide forms and show profile
        registerForm.classList.remove('active');
        loginForm.classList.remove('active');
        profileSection.classList.add('active');

        // Display user information
        userInfo.innerHTML = `
            <p><strong>Username:</strong> ${user.username}</p>
            <p><strong>Display Name:</strong> ${user.displayName}</p>
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Last Login:</strong> ${new Date().toLocaleString()}</p>
        `;
    }

    logout() {
        localStorage.removeItem('userSession');

        // Hide profile and show login form
        document.getElementById('profile-section').classList.remove('active');
        this.showForm('login');

        // Clear form fields
        document.getElementById('login-username').value = '';
        document.getElementById('register-username').value = '';
        document.getElementById('register-email').value = '';
        document.getElementById('register-displayname').value = '';

        this.showMessage('Logged out successfully', 'info');
    }

    checkAuthStatus() {
        const userSession = localStorage.getItem('userSession');
        if (userSession) {
            try {
                const user = JSON.parse(userSession);
                this.showProfile(user);
            } catch (error) {
                localStorage.removeItem('userSession');
            }
        }
    }

    showMessage(message, type = 'info') {
        const statusElement = document.getElementById('status-message');
        statusElement.textContent = message;
        statusElement.className = `status-message ${type}`;
        statusElement.style.display = 'block';

        // Auto-hide success and info messages
        if (type === 'success' || type === 'info') {
            setTimeout(() => {
                this.clearMessage();
            }, 5000);
        }
    }

    clearMessage() {
        const statusElement = document.getElementById('status-message');
        statusElement.style.display = 'none';
        statusElement.textContent = '';
        statusElement.className = 'status-message';
    }

    // Utility functions for base64url encoding/decoding
    arrayBufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    base64urlToArrayBuffer(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padLength = (4 - (base64.length % 4)) % 4;
        const padded = base64 + '='.repeat(padLength);
        const binary = atob(padded);
        const buffer = new ArrayBuffer(binary.length);
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return buffer;
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PasskeyAuth();
});

// Add service worker registration for better PWA experience (optional)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('./sw.js').catch(() => {
            // Service worker registration failed, but that's okay
        });
    });
}