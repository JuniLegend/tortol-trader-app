const AUTH_KEY = 'traderlog_auth_v1';
const INVITES_KEY = 'traderlog_invites_v1';
const ADMIN_CREDS_KEY = 'traderlog_admin_creds_v1';

// FIREBASE CONFIGURATION & CLOUD STORAGE
const firebaseConfig = {
    // TODO: Replace with your actual Firebase project configuration
    apiKey: "YOUR_API_KEY_HERE",
    authDomain: "your-project-id.firebaseapp.com",
    projectId: "your-project-id",
    storageBucket: "your-project-id.appspot.com",
    messagingSenderId: "SENDER_ID",
    appId: "APP_ID"
};

// Initialize Firebase
let db;
let auth;

try {
    if (typeof firebase !== 'undefined') {
        firebase.initializeApp(firebaseConfig);
        db = firebase.firestore();
        auth = firebase.auth();
        console.log("Firebase initialized");
    } else {
        console.warn("Firebase SDK not loaded");
    }
} catch (e) {
    console.warn("Firebase initialization failed (check config):", e);
}

// Cloud Storage Manager
const CloudStorage = {
    async saveFullBackup(appInstance) {
        if (!db) return;

        let docId = null;
        if (auth && auth.currentUser) {
            docId = auth.currentUser.uid;
        } else if (appInstance.currentUser && appInstance.currentUser.username) {
            // Fallback for custom auth
            docId = appInstance.currentUser.username.toLowerCase();
        }

        if (!docId) {
            console.warn("No user identity for cloud save");
            return;
        }

        try {
            // Collect all data
            const data = {
                trades: appInstance.trades || [],
                habits: appInstance.habits || [],
                badHabits: appInstance.badHabits || [],
                habitLogs: appInstance.habitLogs || {},
                settings: appInstance.settings || {},
                last_updated: new Date().toISOString()
            };

            await db.collection('users').doc(docId).set(data, { merge: true });
            console.log("Cloud save successful");

            // UI Feedback
            const btn = document.querySelector('button[onclick="app.backupData()"] span.md\\:block');
            if (btn) {
                const original = btn.textContent;
                btn.textContent = "Saved to Cloud";
                setTimeout(() => { btn.textContent = original; }, 2000);
            }

        } catch (e) {
            console.error("Cloud save failed", e);
        }
    },

    async login(username, password) {
        if (!db) return null;
        try {
            // Check Invites Collection
            const doc = await db.collection('invites').doc(username.toLowerCase()).get();
            if (!doc.exists) return null; // User not found

            const userData = doc.data();
            // Default password check (insecure plain text for prototype)
            // Ideally use extensive Auth, but sticking to requested architecture
            const storedPass = userData.password || 'tortol123';

            if (password === storedPass) {
                return userData;
            }
            return null; // Invalid pass
        } catch (e) {
            console.error("Login fetch failed", e);
            return null;
        }
    },

    async updateProfile(username, newPassword) {
        if (!db) return false;
        try {
            await db.collection('invites').doc(username.toLowerCase()).update({
                password: newPassword
            });
            return true;
        } catch (e) {
            console.error("Profile update failed", e);
            return false;
        }
    },
    async requestPasswordReset(username) {
        if (!db) return false;
        try {
            await db.collection('requests').add({
                username: username,
                type: 'reset',
                status: 'pending',
                timestamp: new Date().toISOString()
            });
            return true;
        } catch (e) {
            console.error("Reset request failed", e);
            return false;
        }
    },

    // Updated getRequests to fetch all pending (access + reset)
    async getRequests() {
        if (!db) return [];
        try {
            const snap = await db.collection('requests').where('status', '==', 'pending').orderBy('timestamp', 'desc').get();
            const requests = [];
            snap.forEach(doc => {
                requests.push({ id: doc.id, ...doc.data() });
            });
            return requests;
        } catch (e) {
            console.error("Fetch requests failed", e);
            return [];
        }
    },

    async approveRequest(requestId, username) {
        if (!db) return;
        try {
            const batch = db.batch();
            const reqRef = db.collection('requests').doc(requestId);
            batch.update(reqRef, { status: 'approved' });

            // Add to public invites list which app checks
            const inviteRef = db.collection('invites').doc(username.toLowerCase());
            batch.set(inviteRef, {
                username: username.toLowerCase(),
                role: 'trader',
                invitedAt: new Date().toISOString()
            });

            await batch.commit();
            return true;
        } catch (e) {
            console.error("Approve failed", e);
            return false;
        }
    },

    async rejectRequest(requestId) {
        if (!db) return;
        try {
            await db.collection('requests').doc(requestId).update({ status: 'rejected' });
            return true;
        } catch (e) {
            console.error("Reject failed", e);
            return false;
        }
    }
};


// Safe Storage Wrapper for file:// protocol support
const SafeStorage = {
    _mem: {},
    get(key) {
        try {
            return localStorage.getItem(key);
        } catch (e) {
            console.warn('Storage read failed, using memory:', e);
            return this._mem[key] || null;
        }
    },
    set(key, val) {
        try {
            localStorage.setItem(key, val);
        } catch (e) {
            console.warn('Storage write failed, using memory:', e);
            this._mem[key] = val;
        }
    },
    remove(key) {
        try {
            localStorage.removeItem(key);
        } catch (e) {
            delete this._mem[key];
        }
    }
};

const app = {
    viewProfile() {
        if (!this.currentUser) return;

        document.getElementById('profile-username').value = this.currentUser.username;
        document.getElementById('profile-role').textContent = this.currentUser.role.toUpperCase();
        document.getElementById('profile-password').value = ''; // Don't show current pass for security

        document.getElementById('modal-profile').classList.remove('hidden');
    },

    async saveProfile() {
        console.log("saveProfile called");
        try {
            const pass = document.getElementById('profile-password').value;
            const confirmPass = document.getElementById('profile-confirm-password').value;

            console.log("Values:", pass, confirmPass);

            if (!pass) return alert("Please enter a new password.");
            if (pass.length < 6) return alert("Password must be at least 6 characters.");
            if (pass !== confirmPass) return alert("Passwords do not match.");

            if (!this.currentUser) {
                console.error("No current user found");
                return alert("Error: User not logged in.");
            }

            console.log("Updating for:", this.currentUser.username);
            const success = await CloudStorage.updateProfile(this.currentUser.username, pass);

            if (success) {
                alert("Password updated successfully.");
                // Update local cache
                const users = this.getInvitedUsers();
                const u = users.find(x => x.username === this.currentUser.username);
                if (u) {
                    u.password = pass;
                    SafeStorage.set(INVITES_KEY, JSON.stringify(users));
                }

                document.getElementById('modal-profile').classList.add('hidden');
            } else {
                alert("Failed to update profile. Please try again.");
            }
        } catch (e) {
            console.error("saveProfile crashed:", e);
            alert("An unexpected error occurred: " + e.message);
        }
    },
    trades: [],
    settings: {
        theme: 'dark', // 'dark' or 'light'
        username: 'Trader'
    },
    currentUser: null,
    currentFilter: 'all',
    // Habit State
    habits: [],
    badHabits: [],
    habitLogs: {}, // { "YYYY-MM-DD": [habitId1, habitId2] }
    habitStreak: 0,

    // Initialization
    init() {
        // Force close all modals on load
        this.closeModals();

        // Auth Initialization
        const auth = SafeStorage.get(AUTH_KEY);

        if (auth) {
            this.currentUser = JSON.parse(auth);
            this.loadData();
            this.applyTheme();
            document.getElementById('login-overlay').classList.add('login-hidden', 'hidden');
            this.updateUserInfo();
            this.renderDashboard();
            const hash = window.location.hash.replace('#', '');
            this.navigate(hash || 'dashboard');
            this.loadDraft();
        } else {
            // Unauthenticated state
            this.trades = [];
            this.applyTheme();
        }

        // Event Listeners for Filters
        document.querySelectorAll('.filter-btn-global').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.setFilter(e.target.dataset.filter);
                document.querySelectorAll('.filter-btn-global').forEach(b => {
                    b.classList.remove('bg-primary', 'text-white', 'font-bold');
                    b.classList.add('text-text-muted-dark', 'font-medium');
                });
                this.renderDashboard();
            });
        });

        // Calculator Event Listeners (Updated for Redesign)
        const calcInputs = ['inputCapital', 'inputRiskSlider', 'inputStopLoss', 'inputRRR', 'inputTicks'];
        calcInputs.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.addEventListener('input', () => this.calculator.calculate());
                el.addEventListener('change', () => this.calculator.calculate());
            }
        });

        // Special listener for slider to update label in real-time
        const slider = document.getElementById('inputRiskSlider');
        if (slider) {
            slider.addEventListener('input', (e) => {
                const label = document.getElementById('labelRiskPercent');
                if (label) label.textContent = `${e.target.value}%`;
            });
        }

        // Initial Calculation
        if (document.getElementById('view-calculator')) {
            setTimeout(() => this.calculator.calculate(), 100);
        }
    },

    async handleLogin() {
        const form = document.getElementById('login-form');
        const user = form.querySelector('[name=username]').value.toLowerCase();
        const pass = form.querySelector('[name=password]').value;

        // Admin Access Check
        const adminCreds = this.getAdminCreds();

        if (user === adminCreds.username.toLowerCase() && pass === adminCreds.password) {
            this.currentUser = { username: adminCreds.username, role: 'admin' };
            this.saveAuth();
            this.loadData();
            this.updateUserInfo();
            this.showApp();
            return;
        }

        // 1. Cloud Check (Priority)
        // This ensures if password changed on cloud, we respect it.
        const cloudUser = await CloudStorage.login(user, pass);
        if (cloudUser) {
            this.currentUser = { username: cloudUser.username, role: cloudUser.role || 'trader' };
            this.saveAuth();

            // Sync this authorized user to local list for offline use next time
            // We pass the PASSWORD too so local knows the new one!
            // Wait, addInvitedUser doesn't take password.
            // We need to manually update the local cache with the new password.
            const invitedUsers = this.getInvitedUsers();
            let localUser = invitedUsers.find(u => u.username === cloudUser.username);

            if (localUser) {
                // Update existing local record
                localUser.password = cloudUser.password || pass; // Store the hash/pass locally
                localUser.role = cloudUser.role;
            } else {
                // Add new local record
                invitedUsers.push({
                    username: cloudUser.username,
                    role: cloudUser.role || 'trader',
                    password: cloudUser.password || pass,
                    invitedAt: new Date().toISOString()
                });
            }
            SafeStorage.set(INVITES_KEY, JSON.stringify(invitedUsers));

            await this.loadCloudData(cloudUser.username);

            this.updateUserInfo();
            this.showApp();
            return;
        }

        // 2. Local Fallback (Only if Cloud failed or offline)
        // NOTE: If Cloud rejected password, we shouldn't really login locally either...
        // But for offline support, we check local storage.
        // Determining "Wrong Password" vs "Offline" is hard without more complex logic.
        // For now, we will perform a strict local check.

        // Remove the hardcoded 'tortol123' fallback unless it IS the password
        let invitedUsers = this.getInvitedUsers();
        let userObj = invitedUsers.find(u => u.username === user);

        if (userObj) {
            // Strict Check: Matches stored password OR matches default IF stored is undefined
            const storedPass = userObj.password || 'tortol123';

            // However, if we just failed Cloud Login with the SAME password, we likely shouldn't allow local?
            // But maybe user is offline. We'll allow it if it matches local knowledge.
            if (pass === storedPass) {
                this.currentUser = { username: userObj.username, role: userObj.role || 'trader' };
                this.saveAuth();
                this.loadData();
                this.updateUserInfo();
                this.showApp();
                return;
            }
        }

        alert("Access Denied. Invalid credentials or user not approved.");
    },

    // Helper to load data from cloud if local is empty
    async loadCloudData(username) {
        if (!db) return;
        try {
            const doc = await db.collection('users').doc(username).get();
            if (doc.exists) {
                const data = doc.data();
                this.trades = data.trades || [];
                this.habits = data.habits || [];
                this.badHabits = data.badHabits || [];
                this.habitLogs = data.habitLogs || {};
                this.settings = data.settings || {};
                this.saveData(); // Save to local cache
                this.saveHabits();
                this.saveSettings();
            }
        } catch (e) {
            console.error("Failed to sync cloud data", e);
        }
    },

    toggleAuthMode(mode) {
        const loginForm = document.getElementById('login-form');
        const signupForm = document.getElementById('signup-form');
        const resetForm = document.getElementById('reset-form');
        const title = document.getElementById('login-title');

        // Hide all first
        loginForm.classList.add('hidden');
        signupForm.classList.add('hidden');
        if (resetForm) resetForm.classList.add('hidden');

        if (mode === 'signup') {
            signupForm.classList.remove('hidden');
            title.textContent = "Request Access";
        } else if (mode === 'reset') {
            if (resetForm) resetForm.classList.remove('hidden');
            title.textContent = "Reset Password";
        } else {
            loginForm.classList.remove('hidden');
            title.textContent = "Tortol Trader Journal";
        }
    },

    async handleResetRequest() {
        const form = document.getElementById('reset-form');
        const username = form.querySelector('[name=reset_username]').value.trim();
        if (!username) return;

        const success = await CloudStorage.requestPasswordReset(username);
        if (success) {
            alert(`Password reset request sent for "${username}".\n\nThe admin will review this shortly.`);
            this.toggleAuthMode('login');
            form.reset();
        } else {
            alert("Request failed. Please try again.");
        }
    },

    async handleSignup() {
        const form = document.getElementById('signup-form');
        const username = form.querySelector('[name=signup_username]').value.trim();

        if (!username) return;

        // Cloud Request
        // alert("Sending request to cloud..."); // Remove debug alert for cleaner UX
        const success = await CloudStorage.requestAccess(username);

        if (success) {
            alert(`Access request sent for "${username}".\n\nPlease wait for admin approval (check back later).`);
            this.toggleAuthMode('login');
            form.reset();
        } else {
            alert("Request failed. Please check your connection or Firebase config.");
        }
    },

    getAdminCreds() {
        const stored = SafeStorage.get(ADMIN_CREDS_KEY);
        // Default credentials if not set
        return stored ? JSON.parse(stored) : { username: 'admin', password: 'admin123' };
    },

    // Data Management: Users & Permissions
    getInvitedUsers() {
        const stored = SafeStorage.get(INVITES_KEY);
        let users = stored ? JSON.parse(stored) : ['junior', 'tortol', 'legend'];

        // Migration: Add permissions array if missing
        if (users.length > 0) {
            let changed = false;
            users = users.map(u => {
                if (typeof u === 'string') {
                    changed = true;
                    // Default legacy migration
                    return { username: u, role: 'trader', permissions: ['dashboard', 'calendar', 'journal', 'entry', 'habits', 'calculator', 'simulator'] };
                }
                if (!u.permissions) {
                    changed = true;
                    // Migrate based on old role
                    if (u.role === 'admin') {
                        u.permissions = ['dashboard', 'calendar', 'journal', 'entry', 'habits', 'calculator', 'simulator', 'admin'];
                    } else if (u.role === 'viewer') {
                        u.permissions = ['dashboard', 'calendar'];
                    } else {
                        u.permissions = ['dashboard', 'calendar', 'journal', 'entry', 'habits', 'calculator', 'simulator'];
                    }
                }
                return u;
            });
            if (changed) SafeStorage.set(INVITES_KEY, JSON.stringify(users));
        }

        return users;
    },

    // --- ADMIN CONSOLE ---

    manageInvites() {
        // Renamed feature in UI to open Admin Console
        if (!this.checkPermission('admin')) return;

        // Show Modal
        document.getElementById('admin-overlay').classList.remove('hidden');

        // Load Profile Data
        const creds = this.getAdminCreds();
        document.getElementById('admin-username-input').value = creds.username;
        document.getElementById('admin-password-input').value = creds.password;

        // Render Users
        this.renderAdminUsers();
    },

    async renderAdminUsers() {
        const users = this.getInvitedUsers();

        // Fetch Cloud Requests
        const pending = await CloudStorage.getRequests();

        const tbody = document.getElementById('admin-user-list');
        const countBadge = document.getElementById('user-count-badge');

        if (countBadge) countBadge.textContent = `${users.length} Active • ${pending.length} Pending`;

        let html = '';

        // Pending Requests First
        pending.forEach(req => {
            const isReset = req.type === 'reset';
            const badgeColor = isReset ? 'bg-indigo-200 dark:bg-indigo-900/50 text-indigo-800 dark:text-indigo-200' : 'bg-amber-200 dark:bg-amber-900/50 text-amber-800 dark:text-amber-200';
            const badgeText = isReset ? 'RESET PASS' : 'REQUEST ACCESS';
            const actionBtn = isReset
                ? `<button onclick="app.adminResetPassword('${req.id}', '${req.username}')" class="text-xs font-bold text-indigo-500 hover:underline mr-3">Reset to Default</button>`
                : `<button onclick="app.adminApproveUser('${req.id}', '${req.username}')" class="text-xs font-bold text-win hover:underline mr-3">Approve</button>`;

            html += `
            <tr class="bg-amber-50 dark:bg-amber-900/10 border-b border-border-light dark:border-border-dark last:border-0">
                <td class="px-4 py-3 font-bold text-amber-600 dark:text-amber-400">
                    ${req.username} <span class="ml-2 text-[10px] uppercase ${badgeColor} px-2 py-0.5 rounded font-black tracking-tighter">${badgeText}</span>
                    <div class="text-[10px] text-text-muted-light dark:text-text-muted-dark font-normal">${new Date(req.timestamp).toLocaleDateString()}</div>
                </td>
                <td class="px-4 py-3 text-text-muted-light dark:text-text-muted-dark text-xs">Action Required</td>
                <td class="px-4 py-3 text-right">
                    ${actionBtn}
                    <button onclick="app.adminRejectUser('${req.id}')" class="text-xs font-bold text-loss hover:underline">Dismiss</button>
                </td>
            </tr>`;
        });

        // Active Users method (unchanged logic mostly)
        users.forEach(u => {
            const permissionCount = u.permissions ? u.permissions.length : 0;
            const isAdmin = u.role === 'admin' || (u.permissions && u.permissions.includes('admin'));

            html += `
            <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors border-b border-border-light dark:border-border-dark last:border-0">
                <td class="px-4 py-3 text-text-main-light dark:text-text-main-dark font-medium">
                    ${u.username}
                    ${isAdmin ? '<span class="ml-2 text-[10px] text-amber-600 font-bold bg-amber-100 dark:bg-amber-900/40 px-1.5 py-0.5 rounded">ADMIN</span>' : ''}
                </td>
                <td class="px-4 py-3">
                    <span class="text-xs text-text-muted-light dark:text-text-muted-dark bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded">
                        ${isAdmin ? 'Full System Access' : `${permissionCount} Features Enabled`}
                    </span>
                </td>
                <td class="px-4 py-3 text-right flex justify-end items-center gap-2">
                    <button onclick="app.editUserAccess('${u.username}')" class="text-xs font-bold text-indigo-500 hover:text-indigo-400 flex items-center gap-1 border border-indigo-500/20 px-2 py-1 rounded hover:bg-indigo-50 dark:hover:bg-indigo-900/10">
                        <span class="material-symbols-outlined text-[14px]">edit</span> Access
                    </button>
                    <button onclick="app.adminRemoveUser('${u.username}')" class="p-1 hover:bg-loss/10 rounded text-loss transition-colors" title="Remove User">
                        <span class="material-symbols-outlined text-sm">delete</span>
                    </button>
                </td>
            </tr>`;
        });

        if (tbody) tbody.innerHTML = html;
    },

    async adminApproveUser(requestId, username) {
        if (confirm(`Approve access for "${username}"?`)) {
            const success = await CloudStorage.approveRequest(requestId, username);
            if (success) {
                // Also add locally for immediate feedback if needed, but renderAdminUsers fetches from cloud
                this.addInvitedUser(username, 'trader', false);
                this.renderAdminUsers();
            } else {
                alert("Approval failed.");
            }
        }
    },

    async adminRejectUser(requestId) {
        if (confirm("Reject this request?")) {
            const success = await CloudStorage.rejectRequest(requestId);
            if (success) this.renderAdminUsers();
        }
    },

    async adminResetPassword(requestId, username) {
        if (confirm(`Reset password for "${username}" to 'tortol123'?`)) {
            // Update profile with default pass
            const success = await CloudStorage.updateProfile(username, 'tortol123');
            if (success) {
                // Mark request as done (basically reject/remove from pending)
                await CloudStorage.rejectRequest(requestId); // Reuse reject to clear from pending list
                this.renderAdminUsers();
                alert(`Password reset for ${username}. Notify them to login with 'tortol123'.`);
            } else {
                alert("Reset failed.");
            }
        }
    },

    adminAddUser() {
        const input = document.getElementById('new-user-input');
        const username = input.value.trim();
        if (!username) return;

        this.addInvitedUser(username, 'trader', true);
        input.value = '';
        this.renderAdminUsers();
    },

    adminRemoveUser(username) {
        if (!this.checkPermission('admin')) return;

        this.showConfirm(`Remove access for user "${username}"?`, () => {
            try {
                let users = this.getInvitedUsers();
                users = users.filter(u => u.username !== username);
                SafeStorage.set(INVITES_KEY, JSON.stringify(users));
                this.renderAdminUsers();
                console.log("User removed.");
            } catch (e) {
                console.error(e);
                alert("Failed to remove user.");
            }
        });
    },

    // ... (rest of admin methods)

    // Habit Tracker Helpers 
    removeBadHabit(index) {
        this.showConfirm("Remove this bad habit tracker?", () => {
            try {
                this.badHabits.splice(index, 1);
                this.saveHabits();
                this.renderHabits();
                console.log("Bad habit removed.");
            } catch (e) {
                console.error("Error removing bad habit:", e);
            }
        });
    },

    // --- NEW: Granular Access Control ---

    editUserAccess(username) {
        const users = this.getInvitedUsers();
        const user = users.find(u => u.username === username);
        if (!user) return;

        document.getElementById('access-username').textContent = username;
        document.getElementById('access-username-hidden').value = username;

        // Reset Checks
        document.querySelectorAll('input[name="access_feature"]').forEach(cb => {
            cb.checked = user.permissions.includes(cb.value);
        });

        document.getElementById('modal-edit-access').classList.remove('hidden');
    },

    saveUserAccess() {
        const username = document.getElementById('access-username-hidden').value;
        const form = document.getElementById('form-edit-access');
        const formData = new FormData(form);
        const selectedFeatures = formData.getAll('access_feature');

        let users = this.getInvitedUsers();
        const user = users.find(u => u.username === username);

        if (user) {
            user.permissions = selectedFeatures;
            // Legacy Backport for existing functions that might rely on role (could remove if full refactor)
            user.role = selectedFeatures.includes('admin') ? 'admin' : 'trader';

            SafeStorage.set(INVITES_KEY, JSON.stringify(users));
            document.getElementById('modal-edit-access').classList.add('hidden');
            this.renderAdminUsers();
        }
    },

    checkPermission(feature) {
        if (!this.currentUser) return false;
        // Super admin override using creds comparison if needed, but per object permissions is better
        // Admin flag implies all permissions normally
        if (this.currentUser.permissions && this.currentUser.permissions.includes('admin')) return true;

        // Specific feature check
        if (this.currentUser.permissions && this.currentUser.permissions.includes(feature)) return true;

        return false;
    },

    adminApproveUser(username) {
        // Default permissions for new approvals
        this.addInvitedUser(username, 'trader', false);

        // Remove from pending
        const PENDING_KEY = 'traderlog_pending_requests_v1';
        let pending = JSON.parse(SafeStorage.get(PENDING_KEY) || '[]');
        pending = pending.filter(u => u !== username);
        SafeStorage.set(PENDING_KEY, JSON.stringify(pending));

        this.renderAdminUsers();
    },

    adminRejectUser(username) {
        this.showConfirm(`Reject request from "${username}"?`, () => {
            const PENDING_KEY = 'traderlog_pending_requests_v1';
            let pending = JSON.parse(SafeStorage.get(PENDING_KEY) || '[]');
            pending = pending.filter(u => u !== username);
            SafeStorage.set(PENDING_KEY, JSON.stringify(pending));

            this.renderAdminUsers();
        });
    },

    handleLogin() {
        const form = document.getElementById('login-form');
        const user = form.querySelector('[name=username]').value.toLowerCase();
        const pass = form.querySelector('[name=password]').value;

        // Admin Access Check
        const adminCreds = this.getAdminCreds();

        if (user === adminCreds.username.toLowerCase() && pass === adminCreds.password) {
            this.currentUser = {
                username: adminCreds.username,
                role: 'admin',
                permissions: ['admin', 'dashboard', 'calendar', 'journal', 'entry', 'habits', 'calculator', 'simulator']
            };
            this.saveAuth();
            this.loadData();
            this.updateUserInfo();
            this.showApp();
            return;
        }

        // Check invited users
        const invitedUsers = this.getInvitedUsers();
        // find user object
        const userObj = invitedUsers.find(u => u.username === user);

        if (userObj && pass === 'tortol123') {
            this.currentUser = {
                username: userObj.username,
                role: userObj.role || 'trader',
                permissions: userObj.permissions || ['dashboard', 'calendar', 'journal', 'entry', 'habits', 'calculator', 'simulator']
            };
            this.saveAuth();
            this.loadData();
            this.updateUserInfo();
            this.showApp();
        } else {
            alert("Access Denied. This app is exclusive for invited Tortol traders.");
        }
    },

    addInvitedUser(username, role = 'trader', showAlert = true) {
        const users = this.getInvitedUsers();
        if (!users.find(u => u.username === username.toLowerCase())) {
            // Default Permissions based on role (legacy support) or just all features for new users
            const defaultPermissions = ['dashboard', 'calendar', 'journal', 'entry', 'habits', 'calculator', 'simulator'];

            users.push({
                username: username.toLowerCase(),
                role,
                permissions: defaultPermissions
            });

            SafeStorage.set(INVITES_KEY, JSON.stringify(users));
            if (showAlert) alert(`User ${username} invited!`);
        }
    },

    updateAdminProfile() {
        const user = document.getElementById('admin-username-input').value.trim();
        const pass = document.getElementById('admin-password-input').value.trim();

        if (!user || !pass) {
            alert("Username and Password are required.");
            return;
        }

        if (pass.length < 6) {
            alert("Password must be at least 6 characters.");
            return;
        }

        const creds = { username: user, password: pass };
        SafeStorage.set(ADMIN_CREDS_KEY, JSON.stringify(creds));
        this.currentUser.username = user; // Update current session too
        this.updateUserInfo();

        alert("Admin credentials updated successfully!");
    },

    saveAuth() {
        SafeStorage.set(AUTH_KEY, JSON.stringify(this.currentUser));
    },

    showApp() {
        document.getElementById('login-overlay').classList.add('login-hidden', 'hidden');
        this.updateUserInfo();
        this.applyTheme(); // Ensure theme is applied

        // Find first available view if dashboard is blocked
        if (this.checkPermission('dashboard')) {
            this.renderDashboard();
            this.navigate('dashboard');
        } else if (this.checkPermission('calendar')) {
            this.navigate('calendar');
        } else {
            // Fallback
            this.navigate('journal');
        }

        this.loadDraft();
    },

    updateUserInfo() {
        if (this.currentUser) {
            const usernameEl = document.getElementById('sidebar-username');
            if (usernameEl) {
                usernameEl.textContent = this.currentUser.username.charAt(0).toUpperCase() + this.currentUser.username.slice(1);
            }

            // Show Admin Elements
            const adminBadge = document.getElementById('admin-badge');
            const inviteNav = document.getElementById('nav-invites');

            if (this.checkPermission('admin')) {
                if (adminBadge) adminBadge.classList.remove('hidden');
                if (inviteNav) inviteNav.classList.remove('hidden');
            } else {
                if (adminBadge) adminBadge.classList.add('hidden');
                if (inviteNav) inviteNav.classList.add('hidden');
            }

            // Toggle Sidebar Items based on Permissions
            const map = {
                'dashboard': 'nav-dashboard',
                'calendar': 'nav-calendar',
                'journal': 'nav-journal',
                'entry': 'nav-entry',
                'habits': 'nav-habits',
                'calculator': 'nav-calculator',
                'simulator': 'nav-simulator'
            };

            for (const [feature, id] of Object.entries(map)) {
                const el = document.getElementById(id);
                if (el) {
                    if (this.checkPermission(feature)) {
                        el.classList.remove('hidden');
                        el.classList.add('flex'); // Restore flex layout
                    } else {
                        el.classList.add('hidden');
                        el.classList.remove('flex');
                    }
                }
            }
        }
    },

    logout() {
        // Immediate logout without confirmation
        SafeStorage.remove(AUTH_KEY);
        this.currentUser = null;
        this.trades = []; // Clear in-memory trades

        // Manual UI Reset
        document.getElementById('login-overlay').classList.remove('login-hidden', 'hidden');
        window.location.hash = '';

        // Hide admin elements
        document.getElementById('admin-badge').classList.add('hidden');
        document.getElementById('nav-invites').classList.add('hidden');

        console.log("Logged out successfully");
    },

    // Data Management
    getStorageKey(baseKey) {
        if (!this.currentUser) return null;
        return `traderlog_${this.currentUser.username}_${baseKey}_v1`;
    },

    getMockData() {
        return [
            {
                id: 1704096000000,
                date: '2026-01-01',
                time: '14:30',
                symbol: 'BTC/USD',
                type: 'Crypto',
                side: 'Long',
                entryPrice: '45000',
                exitPrice: '46500',
                positionSize: '1.5',
                pnl: 2250,
                pnlPercentage: 3.33,
                tradeSetup: 'Trend Following',
                executionSetup: 'Breakout',
                primary_error: 'None',
                emotional_state: 'Calm',
                notes: 'Great start to the year. Clean breakout retest.'
            },
            {
                id: 1704182400000,
                date: '2026-01-02',
                time: '09:15',
                symbol: 'EUR/USD',
                type: 'Forex',
                side: 'Short',
                entryPrice: '1.1050',
                exitPrice: '1.1065',
                positionSize: '100000',
                pnl: -150,
                pnlPercentage: -0.14,
                tradeSetup: 'Reversal',
                executionSetup: 'Double Top',
                primary_error: 'FOMO',
                emotional_state: 'Anxious',
                notes: 'Entered too early before confirmation.'
            }
        ];
    },

    loadData() {
        const dataKey = this.getStorageKey('data');
        const settingsKey = this.getStorageKey('settings');

        if (!dataKey) return;

        const storedData = SafeStorage.get(dataKey);
        const storedSettings = SafeStorage.get(settingsKey);

        if (storedData) {
            this.trades = JSON.parse(storedData);
        } else {
            // Seed mock data for first time user
            this.trades = this.getMockData();
            this.saveData();
        }

        if (storedSettings) {
            this.settings = JSON.parse(storedSettings);
        } else {
            this.settings = { theme: 'dark', username: this.currentUser.username };
            this.saveSettings();
        }

        // Load Habits
        const habitsKey = this.getStorageKey('habits');
        const badHabitsKey = this.getStorageKey('badHabits');
        const habitLogsKey = this.getStorageKey('habitLogs');

        if (habitsKey && SafeStorage.get(habitsKey)) {
            this.habits = JSON.parse(SafeStorage.get(habitsKey));
        } else {
            // Seed Defaults
            this.habits = [
                { id: 1, name: "No FOMO / Candle Close", cue: "Price hits level", craving: "Visualize discipline", reward: "Tick checklist" },
                { id: 2, name: "Pre-Session News Check", cue: "30 mins before bell", craving: "Feel prepared", reward: "Coffee" },
                { id: 3, name: "Log Trade Immediately", cue: "Trade closed", craving: "Peace of mind", reward: "Walk away" }
            ];
            this.saveHabits();
        }

        if (badHabitsKey && SafeStorage.get(badHabitsKey)) {
            this.badHabits = JSON.parse(SafeStorage.get(badHabitsKey));
        }

        if (habitLogsKey && SafeStorage.get(habitLogsKey)) {
            this.habitLogs = JSON.parse(SafeStorage.get(habitLogsKey));
            this.calculateStreak();
        }
    },

    saveData() {
        const key = this.getStorageKey('data');
        if (key) SafeStorage.set(key, JSON.stringify(this.trades));

        // Auto-save to cloud
        CloudStorage.saveFullBackup(this);
    },

    saveSettings() {
        // We're just saving theme and username mostly? 
        // Actually settings object: { theme, username }
        SafeStorage.set('traderlog_settings_v1', JSON.stringify(this.settings));
        CloudStorage.saveFullBackup(this);
    },

    // Draft Management
    saveDraft() {
        const key = this.getStorageKey('draft');
        if (!key) return;

        const form = document.getElementById('trade-form');
        const formData = new FormData(form);
        const data = {};
        formData.forEach((value, key) => {
            if (key !== 'id' && key !== 'image') {
                data[key] = value;
            }
        });
        SafeStorage.set(key, JSON.stringify(data));
        alert("Progress saved! You can continue later.");
    },

    loadDraft() {
        const key = this.getStorageKey('draft');
        if (!key) return;

        const draft = SafeStorage.get(key);
        if (draft) {
            const data = JSON.parse(draft);
            const form = document.getElementById('trade-form');
            Object.keys(data).forEach(key => {
                const el = form.querySelector(`[name=${key}]`);
                if (el) {
                    if (el.type === 'radio') {
                        const radio = form.querySelector(`input[name=${key}][value="${data[key]}"]`);
                        if (radio) radio.checked = true;
                    } else {
                        el.value = data[key];
                    }
                }
            });
            console.log("Draft loaded for " + this.currentUser.username);
        }
    },

    clearDraft() {
        const key = this.getStorageKey('draft');
        if (key) SafeStorage.remove(key);
    },

    // Modal Management
    closeModals() {
        const modals = ['modal-add-habit', 'modal-edit-access', 'admin-overlay', 'modal-add-bad-habit'];
        modals.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add('hidden');
        });
    },

    showConfirm(message, callback) {
        if (window.confirm(message)) {
            callback();
        }
    },

    // Navigation
    navigate(viewId) {
        // PERMISSION GUARD
        if (viewId !== 'dashboard' && !this.checkPermission(viewId)) {
            alert("You do not have permission to access this feature.");
            return;
        }

        // Check dashboard manually (it might be the default view but user might theoretically have it revoked)
        if (viewId === 'dashboard' && !this.checkPermission('dashboard')) {
            // If dashboard is revoked, try to find another view, or stay where we are
            return;
        }

        // Force Hide All Modals
        this.closeModals();

        // Hide all views
        document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));

        // Show target view
        const target = document.getElementById(`view-${viewId}`);
        if (target) {
            target.classList.remove('hidden');
            target.classList.add('animate-fade-in');
        }

        // Update Sidebar Active State
        document.querySelectorAll('.nav-item').forEach(el => {
            el.classList.remove('active', 'bg-slate-100', 'dark:bg-slate-700/50', 'text-primary');
            // Revert to default text color if needed, simplified here by class toggling above
        });

        const navItem = document.getElementById(`nav-${viewId}`);
        if (navItem) {
            navItem.classList.add('active', 'bg-slate-100', 'dark:bg-slate-700/50', 'text-primary');
        }

        // Update URL hash without reload
        history.replaceState(null, null, `#${viewId}`);

        // Trigger specific render functions if needed
        if (viewId === 'dashboard') this.renderDashboard();
        if (viewId === 'journal') this.renderJournal();
        if (viewId === 'calendar') this.renderCalendar();
        if (viewId === 'calculator' && this.calculator) this.calculator.calculate();
        if (viewId === 'simulator' && this.simulator) setTimeout(() => this.simulator.runSimulation(), 100);
        if (viewId === 'habits') this.renderHabits();
    },

    // Form Helpers
    newEntry() {
        if (!this.checkPermission('entry')) {
            alert("You do not have permission to log trades.");
            return;
        }

        if (this.currentView !== 'entry') this.navigate('entry');

        // Clear form
        document.getElementById('trade-form').reset();
        document.querySelector('[name=id]').value = '';

        // Reset Title & Save Button Visibility
        document.getElementById('entry-title').textContent = 'Log New Trade';
        const saveBtn = document.querySelector('button[onclick="app.saveTrade()"]');
        if (saveBtn) saveBtn.style.display = 'flex';

        // Enable inputs
        document.getElementById('trade-form').querySelectorAll('input, select, textarea').forEach(el => el.disabled = false);

        this.clearImage('plan');
        this.clearImage('result');

        // Set default date/time
        const now = new Date();
        const dateStr = now.toISOString().split('T')[0];
        const timeStr = now.toTimeString().split(' ')[0].substring(0, 5);
        document.querySelector('[name=date]').value = dateStr;
        document.querySelector('[name=time]').value = timeStr;

        // Load draft if it exists
        this.loadDraft();

        this.navigate('entry');
    },

    editTrade(id, readOnly = false) {
        const trade = this.trades.find(t => t.id === id);
        if (!trade) return;

        // Populate form
        const form = document.getElementById('trade-form');
        const setVal = (name, val) => {
            const el = form.querySelector(`[name=${name}]`);
            if (el) {
                if (el.type === 'radio') {
                    const radio = form.querySelector(`input[name=${name}][value="${val}"]`);
                    if (radio) radio.checked = true;
                } else {
                    el.value = val || '';
                }
                if (readOnly) el.disabled = true;
                else el.disabled = false;
            }
        };

        setVal('id', trade.id);
        setVal('date', trade.date);
        setVal('time', trade.time);
        setVal('symbol', trade.symbol);
        setVal('type', trade.type);
        setVal('side', trade.side);

        // Execution & PnL
        setVal('timeframe', trade.timeframe);
        setVal('trade_setup', trade.tradeSetup);
        setVal('htf_structure', trade.htfStructure);
        setVal('execution_setup', trade.executionSetup);
        setVal('duration', trade.duration);

        setVal('entry_price', trade.entryPrice);
        setVal('exit_price', trade.exitPrice);
        setVal('position_size', trade.positionSize);
        setVal('pnl_percentage', trade.pnlPercentage);
        setVal('pnl', trade.pnl);

        // Psychology
        setVal('primary_error', trade.primaryError);
        setVal('emotional_state', trade.emotionalState);
        setVal('other_error', trade.otherError);
        setVal('takeaway', trade.takeaway);
        setVal('notes', trade.notes);

        // Update Title & Button
        document.getElementById('entry-title').textContent = readOnly ? 'View Trade' : 'Edit Trade';
        const saveBtn = document.querySelector('button[onclick="app.saveTrade()"]');
        if (saveBtn) {
            saveBtn.style.display = readOnly ? 'none' : 'flex';
        }

        // Image Protection (Hide close buttons in View mode)
        const closeBtns = document.querySelectorAll('#image-preview-container-plan button, #image-preview-container-result button');
        closeBtns.forEach(btn => {
            btn.style.display = readOnly ? 'none' : 'block';
        });

        // Images
        this.clearImage('plan');
        this.clearImage('result');

        const loadImg = (key, type) => {
            const imgData = trade[key];
            if (imgData) {
                const preview = document.getElementById(`image-preview-${type}`);
                const container = document.getElementById(`image-preview-container-${type}`);
                preview.src = imgData;
                container.classList.remove('hidden');
                form.dataset[`existingImage${type.charAt(0).toUpperCase() + type.slice(1)}`] = imgData;
            } else {
                delete form.dataset[`existingImage${type.charAt(0).toUpperCase() + type.slice(1)}`];
            }
        };

        // Handle Legacy 'image' field by assigning it to Result if imageResult missing
        if (trade.image && !trade.imageResult) trade.imageResult = trade.image;

        loadImg('imagePlan', 'plan');
        loadImg('imageResult', 'result');

        this.navigate('entry');
    },

    clearImage(type) {
        if (!type) {
            // Clear all if no type spec (safe fallback)
            this.clearImage('plan');
            this.clearImage('result');
            return;
        }
        const input = document.getElementById(`trade-image-input-${type}`);
        if (input) input.value = '';
        document.getElementById(`image-preview-container-${type}`).classList.add('hidden');
        document.getElementById(`image-preview-${type}`).src = '';
        delete document.getElementById('trade-form').dataset[`existingImage${type.charAt(0).toUpperCase() + type.slice(1)}`];
    },

    // Theme Logic
    toggleTheme() {
        this.settings.theme = this.settings.theme === 'dark' ? 'light' : 'dark';
        this.saveSettings();
        this.applyTheme();
    },

    applyTheme() {
        const html = document.documentElement;
        if (this.settings.theme === 'dark') {
            html.classList.add('dark');
        } else {
            html.classList.remove('dark');
        }
    },

    // Filtering
    setFilter(category) {
        this.currentFilter = category;
        this.renderDashboard(); // Re-render dashboard with filter
    },

    getFilteredTrades() {
        if (this.currentFilter === 'all') return this.trades;
        return this.trades.filter(t => t.type === this.currentFilter);
    },

    viewImage(id, type = 'result') {
        const trade = this.trades.find(t => t.id === id);
        if (!trade) return;

        // Fallback for legacy
        let imgSrc = (type === 'plan') ? trade.imagePlan : (trade.imageResult || trade.image);

        if (imgSrc) {
            // Open in new window safely
            const win = window.open("");
            if (win) {
                win.document.write(`<div style="display:flex;justify-content:center;background:#111;height:100vh;align-items:center;"><img src="${imgSrc}" style="max-width: 95%; max-height: 95vh; border: 2px solid #333;"></div>`);
                win.document.title = `Trade Image (${type})`;
                win.document.body.style.margin = "0";
            } else {
                alert("Please allow popups to view images.");
            }
        } else {
            alert(`No ${type} image found.`);
        }
    },

    // Core Features
    async saveTrade() {
        const form = document.getElementById('trade-form');
        const formData = new FormData(form);
        const id = formData.get('id');

        // Handle Image Logic
        const processImage = async (type) => {
            let base64 = form.dataset[`existingImage${type.charAt(0).toUpperCase() + type.slice(1)}`] || null;
            const input = document.getElementById(`trade-image-input-${type}`);
            if (input && input.files && input.files[0]) {
                try {
                    base64 = await this.readFileAsDataURL(input.files[0]);
                } catch (e) {
                    console.error(`Error reading ${type} file`, e);
                }
            }
            return base64;
        };

        const imagePlanBase64 = await processImage('plan');
        const imageResultBase64 = await processImage('result');

        const tradeData = {
            id: id ? parseInt(id) : Date.now(),
            date: formData.get('date'),
            time: formData.get('time'),
            symbol: formData.get('symbol').toUpperCase(),
            type: formData.get('type'),
            side: formData.get('side'),
            // New Fields
            timeframe: formData.get('timeframe'),
            tradeSetup: formData.get('trade_setup'),
            htfStructure: formData.get('htf_structure'),
            executionSetup: formData.get('execution_setup'),
            duration: formData.get('duration'),

            entryPrice: formData.get('entry_price'),
            exitPrice: formData.get('exit_price'),
            positionSize: formData.get('position_size'),
            pnlPercentage: formData.get('pnl_percentage'),
            pnl: parseFloat(formData.get('pnl')),
            // Psychology
            primary_error: formData.get('primary_error'),
            other_error: formData.get('other_error'),
            emotional_state: formData.get('emotional_state'),
            takeaway: formData.get('takeaway'),
            // Legacy/Combined
            tag: formData.get('primary_error') === 'Other' ? formData.get('other_error') : formData.get('primary_error'), // Map primary error to 'tag' for simple display in journal
            notes: formData.get('notes'),
            imagePlan: imagePlanBase64,
            imageResult: imageResultBase64
        };

        if (id) {
            // Update existing
            const index = this.trades.findIndex(t => t.id === parseInt(id));
            if (index !== -1) {
                this.trades[index] = tradeData;
            }
        } else {
            // Create New
            this.trades.unshift(tradeData);
        }

        this.saveData();
        this.clearDraft(); // Clear progress after successful save
        form.reset();
        this.clearImage();
        this.navigate('dashboard');
    },

    readFileAsDataURL(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsDataURL(file);
        });
    },

    // Renders
    // Advanced Analytics State
    pnlChart: null,
    lossInstrumentChart: null,
    currentChartPeriod: 'ALL',

    // Helper: Get Trades for Current Dashboard Period
    getTradesForPeriod() {
        let trades = [...this.getFilteredTrades()];

        // Filter by Period
        const now = new Date();
        const cutoff = new Date(); // Start with clear date
        let hasFilter = false;

        if (this.currentChartPeriod === '1W') {
            cutoff.setDate(now.getDate() - 7);
            hasFilter = true;
        } else if (this.currentChartPeriod === '1M') {
            cutoff.setMonth(now.getMonth() - 1);
            hasFilter = true;
        } else if (this.currentChartPeriod === '3M') {
            cutoff.setMonth(now.getMonth() - 3);
            hasFilter = true;
        } else if (this.currentChartPeriod === 'YTD') {
            cutoff.setMonth(0, 1); // Jan 1st of current year
            hasFilter = true;
        }

        if (hasFilter) {
            // Filter trades where date >= cutoff
            // Trace date strings YYYY-MM-DD
            trades = trades.filter(t => new Date(t.date) >= cutoff);
        }

        return trades;
    },

    updateTimeFilter(period) {
        this.currentChartPeriod = period;
        this.renderDashboard();
    },

    // Community Data Aggregation
    aggregateCommunityData() {
        // scan all keys matching traderlog_*_data_v1
        const allData = [];
        const users = this.getInvitedUsers();

        users.forEach(u => {
            const key = `traderlog_${u.username}_data_v1`;
            const raw = SafeStorage.get(key);
            if (raw) {
                const trades = JSON.parse(raw);
                // Tag trades with username for attribution
                trades.forEach(t => t._username = u.username);
                allData.push(...trades);
            }
        });

        return allData;
    },

    renderCommunityStats() {
        const allTrades = this.aggregateCommunityData();
        if (allTrades.length === 0) return;

        // 1. Top Mistake
        const mistakeCounts = {};
        allTrades.forEach(t => {
            if (t.pnl < 0 && t.primary_error && t.primary_error !== 'None') {
                mistakeCounts[t.primary_error] = (mistakeCounts[t.primary_error] || 0) + 1;
            }
        });
        const topMistake = Object.entries(mistakeCounts).sort((a, b) => b[1] - a[1])[0];
        if (topMistake) {
            document.getElementById('comm-top-mistake').textContent = topMistake[0];
            document.getElementById('comm-mistake-stat').textContent = `Across ${allTrades.length} trades`;
        }

        // 2. Top Trader
        const traderPnL = {};
        allTrades.forEach(t => {
            traderPnL[t._username] = (traderPnL[t._username] || 0) + t.pnl;
        });
        const topTrader = Object.entries(traderPnL).sort((a, b) => b[1] - a[1])[0];
        if (topTrader) {
            document.getElementById('comm-top-trader').textContent = '@' + topTrader[0];
            document.getElementById('comm-trader-stat').textContent = `Total PnL: $${topTrader[1].toFixed(0)}`;
        }

        // 3. Most Winning Setup
        const setWinCounts = {};
        allTrades.forEach(t => {
            if (t.pnl > 0 && t.tradeSetup) {
                const s = t.tradeSetup;
                if (!setWinCounts[s]) setWinCounts[s] = { count: 0, pnl: 0 };
                setWinCounts[s].count++;
                setWinCounts[s].pnl += t.pnl;
            }
        });
        // Sort by Total PnL generated
        const topSetup = Object.entries(setWinCounts).sort((a, b) => b[1].pnl - a[1].pnl)[0];
        if (topSetup) {
            document.getElementById('comm-win-setup').textContent = topSetup[0];
            document.getElementById('comm-win-setup-stat').textContent = `Generated $${topSetup[1].pnl.toFixed(0)}`;
        }

        // 4. Hardest Setup (Most Losing)
        const setLossCounts = {};
        allTrades.forEach(t => {
            if (t.pnl < 0 && t.tradeSetup) {
                const s = t.tradeSetup;
                if (!setLossCounts[s]) setLossCounts[s] = { count: 0, pnl: 0 };
                setLossCounts[s].count++;
                setLossCounts[s].pnl += Math.abs(t.pnl);
            }
        });
        const worstSetup = Object.entries(setLossCounts).sort((a, b) => b[1].pnl - a[1].pnl)[0]; // Sort by max loss amount
        if (worstSetup) {
            document.getElementById('comm-loss-setup').textContent = worstSetup[0];
            document.getElementById('comm-loss-setup-stat').textContent = `Lost $${worstSetup[1].pnl.toFixed(0)}`;
        }
    },

    calculateAdvancedStats(periodTrades) {
        let totalWinPnl = 0;
        let totalLossPnl = 0;
        let winCount = 0;
        let lossCount = 0;

        periodTrades.forEach(t => {
            if (t.pnl > 0) {
                totalWinPnl += t.pnl;
                winCount++;
            } else if (t.pnl < 0) {
                totalLossPnl += Math.abs(t.pnl);
                lossCount++;
            }
        });

        // Metrics
        const profitFactor = totalLossPnl === 0 ? (totalWinPnl > 0 ? "∞" : "0.00") : (totalWinPnl / totalLossPnl).toFixed(2);
        const avgWin = winCount > 0 ? totalWinPnl / winCount : 0;
        const avgLoss = lossCount > 0 ? totalLossPnl / lossCount : 0;
        const rrr = avgLoss === 0 ? (avgWin > 0 ? "∞" : "0.00") : (avgWin / avgLoss).toFixed(2);

        return { profitFactor, rrr, avgWin, avgLoss };
    },

    renderDashboard() {
        // Data Prep
        const allTrades = [...this.trades].sort((a, b) => new Date(`${b.date}T${b.time}`) - new Date(`${a.date}T${a.time}`));
        const periodTrades = this.getTradesForPeriod();

        // 1. Render KPIs
        this.renderKPIs(periodTrades);

        // 2. Render Recent Trades (Global List)
        this.renderRecentTrades(allTrades.slice(0, 5));

        // 3. Render Community Stats (Admin/Analyst Only)
        const statsContainer = document.getElementById('community-stats-container');
        if (statsContainer) {
            const role = this.currentUser?.role;
            if (role === 'admin' || role === 'analyst') {
                statsContainer.classList.remove('hidden');
                this.renderCommunityStats();
            } else {
                statsContainer.classList.add('hidden');
            }
        }

        // 4. Render Advanced Metrics (Profit Factor, etc.)
        this.renderAdvancedMetrics(periodTrades);

        // 4. Render Charts & Widgets (with slight delay for Canvas)
        setTimeout(() => {
            this.renderPnLChart(periodTrades);
            this.renderLossAnalysis(periodTrades);
            this.renderInstrumentAnalysis(periodTrades);
            this.renderLossAnalysis(periodTrades);
            this.renderInstrumentAnalysis(periodTrades);
            this.renderTopWinners(periodTrades);
            this.renderTopLosers(periodTrades);

            // New Analytics
            this.renderSetupAnalysis(periodTrades);
            this.renderExecutionAnalysis(periodTrades);
            this.renderTimeframeAnalysis(periodTrades);
        }, 0);

        // Update Filter Buttons UX
        this.updateFilterButtons();
    },

    renderKPIs(trades) {
        let totalPnL = 0;
        let wins = 0;
        let losses = 0;

        trades.forEach(t => {
            totalPnL += t.pnl;
            if (t.pnl > 0) wins++;
            else if (t.pnl < 0) losses++;
        });

        const totalTrades = wins + losses;
        const winRate = totalTrades > 0 ? Math.round((wins / totalTrades) * 100) : 0;
        const profitFactor = (Math.abs(totalPnL) > 0 && losses > 0) ? "N/A" : "0.00"; // Placeholder calc, simpler here
        const avgTrade = totalTrades > 0 ? (totalPnL / totalTrades).toFixed(2) : "0.00";

        // Update DOM elements by ID instead of overwriting innerHTML
        // Net PnL
        const pnlEl = document.getElementById('dash-net-pnl');
        if (pnlEl) {
            pnlEl.textContent = `$${totalPnL.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
            pnlEl.className = `text-2xl font-black tracking-tight ${totalPnL >= 0 ? 'text-win' : 'text-loss'}`;
        }

        // Win Rate
        const winRateEl = document.getElementById('dash-win-rate');
        if (winRateEl) winRateEl.textContent = `${winRate}%`;

        // Profit Factor (Recalculating simpler version here or use from advanced stats)
        // Check renderAdvancedMetrics for consistency, but this is the top box
        // We'll update renderDashboard to pass stats or just do basic here.
        // Actually, let's keep it simple and consistent. IDs: dash-profit-factor, dash-avg-trade

        const pfEl = document.getElementById('dash-profit-factor');
        // Let's defer PF to renderAdvancedMetrics or calculate it here properly if we want live sync.
        // Quick calc:
        let grossWin = 0;
        let grossLoss = 0;
        trades.forEach(t => { if (t.pnl > 0) grossWin += t.pnl; else grossLoss += Math.abs(t.pnl); });
        const pf = grossLoss === 0 ? (grossWin > 0 ? "∞" : "0.00") : (grossWin / grossLoss).toFixed(2);
        if (pfEl) pfEl.textContent = pf;

        const avgEl = document.getElementById('dash-avg-trade');
        if (avgEl) {
            avgEl.textContent = `$${avgTrade}`;
            avgEl.className = `text-2xl font-black tracking-tight ${parseFloat(avgTrade) >= 0 ? 'text-win' : 'text-loss'}`;
        }

        const totalEl = document.getElementById('dash-total-trades');
        if (totalEl) totalEl.textContent = totalTrades;
    },

    renderRecentTrades(trades) {
        const rows = trades.map(t => `
            <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors border-b border-border-light dark:border-border-dark last:border-0">
                <td class="px-4 py-3 text-text-main-light dark:text-text-main-dark whitespace-nowrap">${t.date}</td>
                <td class="px-4 py-3 font-bold text-text-main-light dark:text-text-main-dark">${t.symbol}</td>
                <td class="px-4 py-3">
                    <span class="px-2 py-1 rounded text-xs font-bold ${t.side === 'Long' ? 'bg-win-soft text-win' : 'bg-loss-soft text-loss'}">${t.side}</span>
                </td>
                <td class="px-4 py-3 text-right font-bold ${t.pnl >= 0 ? 'text-win' : 'text-loss'}">${t.pnl >= 0 ? '+' : ''}$${t.pnl.toFixed(2)}</td>
            </tr>
        `).join('');
        const tbody = document.getElementById('dashboard-recent-trades-body');
        if (tbody) tbody.innerHTML = rows;
    },

    renderAdvancedMetrics(trades) {
        // IDs in HTML: dash-profit-factor, dash-rrr (missing in HTML, skipping), dash-avg-win (missing), dash-avg-loss (missing)
        // We only have dash-profit-factor in the main grid. The others are not in index.html (removed or never added).
        // So we can largely skip this or just ensure Profit Factor is updated here if not in renderKPIs.
        // renderKPIs handles dash-profit-factor basics.
    },

    updateFilterButtons() {
        // Global Filter Buttons
        document.querySelectorAll('.filter-btn-global').forEach(btn => {
            const filter = btn.dataset.filter;
            if (filter === this.currentFilter) {
                btn.className = 'filter-btn-global px-3 py-1.5 rounded text-xs font-bold transition-all text-white bg-primary';
            } else {
                btn.className = 'filter-btn-global px-3 py-1.5 rounded text-xs font-medium transition-all text-text-muted-light dark:text-text-muted-dark hover:bg-slate-100 dark:hover:bg-slate-700';
            }
        });

        // Time Period Buttons
        // Time Period Buttons (Chart Filters)
        document.querySelectorAll('.filter-btn').forEach(btn => {
            if (btn.dataset.filter === this.currentChartPeriod) {
                // Active State
                btn.className = "filter-btn active px-3 py-1 text-xs font-bold rounded-lg bg-primary text-white shadow-md shadow-primary/20 transition-colors";
            } else {
                // Inactive State
                btn.className = "filter-btn px-3 py-1 text-xs font-bold rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-text-muted-light dark:text-text-muted-dark";
            }
        });
    },

    // --- CHARTS & WIDGETS ---

    renderPnLChart(trades) {
        const ctx = document.getElementById('chart-pnl').getContext('2d');
        let chartTrades = [...trades];
        // Sort by Date Ascending
        chartTrades.sort((a, b) => new Date(`${a.date}T${a.time}`) - new Date(`${b.date}T${b.time}`));

        // Prepare Data Points
        let cumulative = 0;
        const dataPoints = chartTrades.map(t => {
            cumulative += t.pnl;
            return { x: t.date, y: cumulative };
        });

        const labels = dataPoints.map(d => d.x);
        const data = dataPoints.map(d => d.y);
        const color = cumulative >= 0 ? '#10b981' : '#ef4444';

        if (this.pnlChart) this.pnlChart.destroy();

        this.pnlChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Cumulative P&L',
                    data: data,
                    borderColor: color,
                    backgroundColor: (context) => {
                        const ctx = context.chart.ctx;
                        const gradient = ctx.createLinearGradient(0, 0, 0, 300);
                        gradient.addColorStop(0, cumulative >= 0 ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)');
                        gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
                        return gradient;
                    },
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 2,
                    pointHoverRadius: 5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: { mode: 'index', intersect: false }
                },
                scales: {
                    x: { display: false },
                    y: { grid: { color: document.documentElement.classList.contains('dark') ? '#334155' : '#e2e8f0' } }
                }
            }
        });
    },

    renderLossAnalysis(trades) {
        const ctx = document.getElementById('chart-loss-reasons').getContext('2d');
        const losses = trades.filter(t => t.pnl < 0);

        if (this.lossReasonChart) this.lossReasonChart.destroy(); // assuming added to state or using generic local var

        // Group by Primary Error
        const counts = {};
        losses.forEach(t => {
            const error = t.primary_error || "Uncategorized";
            if (!counts[error]) counts[error] = 0;
            counts[error] += Math.abs(t.pnl);
        });

        // Sort Top 5
        const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
        const labels = sorted.map(i => i[0]);
        const data = sorted.map(i => i[1]);

        if (window.lossReasonChartInstance) window.lossReasonChartInstance.destroy();

        window.lossReasonChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Loss Amount ($)',
                    data: data,
                    backgroundColor: '#ef4444',
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y', // Horizontal Bar
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } },
                    y: { grid: { display: false } }
                }
            }
        });
    },

    renderInstrumentAnalysis(trades) {
        const ctx = document.getElementById('chart-asset-class').getContext('2d');
        // We want performance by asset class (Type) - maybe just gross PnL or volume? 
        // Let's do Distribution of Trades by Type for now, or Net PnL by Type (green/red)
        // Prompt asked for "Performance", but doughnut is usually for distribution.
        // Let's stick to Distribution of Volume (count) or PnL Magnitude.
        // Let's do PnL Magnitude (absolute value activity).

        const counts = {};
        trades.forEach(t => {
            const type = t.type || "Other";
            if (!counts[type]) counts[type] = 0;
            counts[type] += Math.abs(t.pnl);
        });

        const labels = Object.keys(counts);
        const data = Object.values(counts);
        const colors = ['#6366f1', '#10b981', '#ef4444', '#f59e0b', '#8b5cf6'];

        if (window.assetClassChartInstance) window.assetClassChartInstance.destroy();

        window.assetClassChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { boxWidth: 12, usePointStyle: true } }
                }
            }
        });
    },

    renderTopWinners(trades) {
        const winners = trades.filter(t => t.pnl > 0).sort((a, b) => b.pnl - a.pnl).slice(0, 10);
        const tbody = document.getElementById('table-top-winners');
        if (!tbody) return;

        tbody.innerHTML = winners.map(t => `
            <tr>
                <td class="py-2 text-text-main-light dark:text-text-main-dark font-bold">${t.symbol}</td>
                <td class="py-2 text-right text-win font-mono">+$${t.pnl.toLocaleString()}</td>
            </tr>
        `).join('');
    },

    renderTopLosers(trades) {
        const losers = trades.filter(t => t.pnl < 0).sort((a, b) => a.pnl - b.pnl).slice(0, 10); // Ascending (most negative first)
        const tbody = document.getElementById('table-top-losers');
        if (!tbody) return;

        tbody.innerHTML = losers.map(t => `
            <tr>
                <td class="py-2 text-text-main-light dark:text-text-main-dark font-bold">${t.symbol}</td>
                <td class="py-2 text-right text-loss font-mono">$${t.pnl.toLocaleString()}</td>
            </tr>
        `).join('');
    },

    renderSetupAnalysis(trades) {
        const setups = {};
        trades.forEach(t => {
            const s = t.tradeSetup || 'Other';
            if (!setups[s]) setups[s] = 0;
            setups[s] += t.pnl;
        });

        const ctx = document.getElementById('chart-setups').getContext('2d');
        if (window.setupChartInstance) window.setupChartInstance.destroy();

        window.setupChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Object.keys(setups),
                datasets: [{
                    label: 'Net PnL by Setup',
                    data: Object.values(setups),
                    backgroundColor: Object.values(setups).map(v => v >= 0 ? 'rgba(16, 185, 129, 0.6)' : 'rgba(239, 68, 68, 0.6)'),
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: { x: { grid: { display: false } }, y: { grid: { display: false } } }
            }
        });
    },

    renderExecutionAnalysis(trades) {
        const stats = {};
        trades.forEach(t => {
            const e = t.executionSetup || 'Other';
            if (!stats[e]) stats[e] = { win: 0, loss: 0 };
            if (t.pnl >= 0) stats[e].win++;
            else stats[e].loss++;
        });

        const labels = Object.keys(stats);
        const winData = labels.map(l => stats[l].win);
        const lossData = labels.map(l => stats[l].loss);

        const ctx = document.getElementById('chart-execution').getContext('2d');
        if (window.executionChartInstance) window.executionChartInstance.destroy();

        window.executionChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    { label: 'Wins', data: winData, backgroundColor: 'rgba(16, 185, 129, 0.6)' },
                    { label: 'Losses', data: lossData, backgroundColor: 'rgba(239, 68, 68, 0.6)' }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { boxWidth: 12 } } },
                scales: { x: { stacked: false }, y: { grid: { display: false } } }
            }
        });
    },

    renderTimeframeAnalysis(trades) {
        const counts = {};
        trades.forEach(t => {
            const tf = t.timeframe || 'N/A';
            counts[tf] = (counts[tf] || 0) + 1;
        });

        const ctx = document.getElementById('chart-timeframes').getContext('2d');
        if (window.tfChartInstance) window.tfChartInstance.destroy();

        window.tfChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(counts),
                datasets: [{
                    data: Object.values(counts),
                    backgroundColor: ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { boxWidth: 12, usePointStyle: true } }
                }
            }
        });
    },


    renderJournal() {
        // Full list table
        const rows = this.trades.map(t => `
             <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors group">
                <td class="px-6 py-4 text-text-main-light dark:text-text-main-dark whitespace-nowrap">${t.date} <span class="text-xs text-text-muted-light dark:text-text-muted-dark ml-1">${t.time}</span></td>
                <td class="px-6 py-4 font-bold text-text-main-light dark:text-text-main-dark">
                    <div class="flex flex-col">
                        <span>${t.symbol}</span>
                        <span class="text-xs font-normal text-text-muted-light dark:text-text-muted-dark">${t.type}</span>
                    </div>
                </td>
                <td class="px-6 py-4">
                    <span class="px-2 py-1 rounded text-xs font-bold ${t.side === 'Long' ? 'bg-win-soft text-win' : 'bg-loss-soft text-loss'}">${t.side}</span>
                </td>
                <td class="px-6 py-4">
                    ${t.tag ? `<span class="px-2 py-1 rounded bg-slate-100 dark:bg-slate-700 text-xs font-medium text-text-muted-light dark:text-text-muted-dark">${t.tag}</span>` : '-'}
                </td>
                 <td class="px-6 py-4">
                    <div class="flex flex-col gap-1">
                        ${(t.imagePlan) ? `<button onclick="app.viewImage(${t.id}, 'plan')" class="text-text-muted-light dark:text-text-muted-dark hover:text-primary text-xs font-bold flex items-center gap-1"><span class="material-symbols-outlined text-[14px]">architecture</span> Plan</button>` : ''}
                        ${(t.imageResult || t.image) ? `<button onclick="app.viewImage(${t.id}, 'result')" class="text-text-muted-light dark:text-text-muted-dark hover:text-primary text-xs font-bold flex items-center gap-1"><span class="material-symbols-outlined text-[14px]">image</span> Result</button>` : ''}
                        ${(!t.imagePlan && !t.imageResult && !t.image) ? '<span class="text-xs text-text-muted-light dark:text-text-muted-dark">-</span>' : ''}
                    </div>
                </td>
                <td class="px-6 py-4 text-right font-bold ${t.pnl >= 0 ? 'text-win' : 'text-loss'}">${t.pnl >= 0 ? '+' : ''}$${t.pnl.toFixed(2)}</td>
                <td class="px-6 py-4 text-center">
                    <div class="flex items-center justify-center gap-2">
                        <button onclick="app.editTrade(${t.id}, true)" class="text-text-muted-light dark:text-text-muted-dark hover:text-info transition-colors p-1" title="View">
                            <span class="material-symbols-outlined text-[20px]">visibility</span>
                        </button>
                        <button onclick="app.editTrade(${t.id})" class="text-text-muted-light dark:text-text-muted-dark hover:text-primary transition-colors p-1" title="Edit">
                            <span class="material-symbols-outlined text-[20px]">edit</span>
                        </button>
                        <button onclick="app.deleteTrade('${t.id}')" class="text-text-muted-light dark:text-text-muted-dark hover:text-loss transition-colors p-1" title="Delete">
                            <span class="material-symbols-outlined text-[20px]">delete</span>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');

        document.getElementById('journal-table-body').innerHTML = rows;
        document.getElementById('journal-count').textContent = `${this.trades.length} total trades`;
    },

    // Calendar State
    currentViewDate: new Date(),

    changeMonth(offset) {
        // Update date
        this.currentViewDate.setMonth(this.currentViewDate.getMonth() + offset);
        this.renderCalendar();
    },

    renderCalendar() {
        const grid = document.getElementById('calendar-grid');
        grid.innerHTML = ''; // Clear

        const year = this.currentViewDate.getFullYear();
        const month = this.currentViewDate.getMonth(); // 0-11

        // Update Header
        const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
        document.getElementById('calendar-month-year').textContent = `${monthNames[month]} ${year}`;

        const firstDay = new Date(year, month, 1).getDay(); // 0 (Sun) - 6 (Sat)
        const daysInMonth = new Date(year, month + 1, 0).getDate();

        // Empty cells for previous month
        for (let i = 0; i < firstDay; i++) {
            grid.innerHTML += `<div class="bg-surface-light dark:bg-surface-dark opacity-30 min-h-[100px] border border-transparent"></div>`;
        }

        // Days
        for (let d = 1; d <= daysInMonth; d++) {
            // Find trades for this day
            // Note: date input gives 'YYYY-MM-DD'
            const dateStr = `${year}-${String(month + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
            const dayTrades = this.trades.filter(t => t.date === dateStr);

            let dayPnL = 0;
            dayTrades.forEach(t => dayPnL += t.pnl);

            const cell = document.createElement('div');
            cell.className = 'bg-surface-light dark:bg-surface-dark min-h-[100px] p-2 border border-transparent hover:border-primary/30 hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-all cursor-pointer flex flex-col justify-between';

            const hasTrades = dayTrades.length > 0;
            const pnlClass = dayPnL >= 0 ? 'text-win' : 'text-loss';

            cell.innerHTML = `
                <div class="flex justify-between items-start">
                    <span class="text-sm font-bold ${hasTrades ? 'text-text-main-light dark:text-text-main-dark' : 'text-text-muted-light dark:text-text-muted-dark'}">${d}</span>
                    ${hasTrades ? `<span class="text-[10px] bg-slate-100 dark:bg-slate-700 px-1 rounded">${dayTrades.length}</span>` : ''}
                </div>
                ${hasTrades ? `
                    <div class="mt-1">
                        <p class="text-xs font-bold font-mono ${pnlClass}">${dayPnL >= 0 ? '+' : ''}${dayPnL.toFixed(2)}</p>
                         <div class="flex gap-1 mt-1">
                            ${dayTrades.map(t => `<div class="size-1.5 rounded-full ${t.pnl >= 0 ? 'bg-win' : 'bg-loss'}"></div>`).join('').slice(0, 5)}
                         </div>
                    </div>
                ` : ''}
            `;
            grid.appendChild(cell);
        }
    },

    deleteTrade(id) {
        this.showConfirm('Are you sure you want to delete this trade? This cannot be undone.', () => {
            console.log("Deleting trade:", id);
            const originalLength = this.trades.length;

            // Try number first (most likely), then string (UUIDs)
            // Loose comparison cover both, but let's be explicit if we want
            this.trades = this.trades.filter(t => t.id != id);

            if (this.trades.length === originalLength) {
                // Fallback for strict string mismatch
                this.trades = this.trades.filter(t => String(t.id) !== String(id));
            }

            this.saveData();
            this.renderJournal();
            this.renderDashboard();
            console.log("Trade deleted.");
        });
    },


    calculator: {
        calculate() {
            const getVal = (id) => parseFloat(document.getElementById(id)?.value) || 0;

            const capital = getVal('inputCapital');
            const riskPercent = getVal('inputRiskSlider');
            const stopLossPercent = getVal('inputStopLoss');
            const rrr = getVal('inputRRR');

            // Update labels
            const labelRisk = document.getElementById('labelRiskPercent');
            if (labelRisk) labelRisk.textContent = `${riskPercent}%`;

            // 1. Calculate Risk Amount (Capital * Risk%)
            const riskAmount = capital * (riskPercent / 100);

            // 2. Calculate Position Size
            // Position Size = (Risk Amount) / (Stop Loss %)
            let positionSize = 0;
            if (stopLossPercent > 0) {
                positionSize = riskAmount / (stopLossPercent / 100);
            }

            // 3. Calculate Potential Profit
            const profitAmount = riskAmount * rrr;

            // 4. Update UI
            const els = {
                displayRiskAmount: document.getElementById('displayRiskAmount'),
                displayPositionSize: document.getElementById('displayPositionSize'),
                displayProfitAmount: document.getElementById('displayProfitAmount'),
                displayRiskPercentHero: document.getElementById('displayRiskPercentHero'),
                displaySLPercentHero: document.getElementById('displaySLPercentHero'),
                displayTargetTicks: document.getElementById('displayTargetTicks')
            };

            if (els.displayRiskAmount) els.displayRiskAmount.textContent = `-$${riskAmount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
            if (els.displayPositionSize) els.displayPositionSize.textContent = `$${positionSize.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
            if (els.displayProfitAmount) els.displayProfitAmount.textContent = `+$${profitAmount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

            if (els.displayRiskPercentHero) els.displayRiskPercentHero.textContent = `${riskPercent}%`;
            if (els.displaySLPercentHero) els.displaySLPercentHero.textContent = `${stopLossPercent}%`;

            // Ticks
            const ticks = getVal('inputTicks');
            if (els.displayTargetTicks) els.displayTargetTicks.textContent = `${(ticks * rrr).toFixed(0)} Ticks`;

            // Render Leverage Table
            this.renderLeverageTable(capital, stopLossPercent, positionSize);
        },

        setRisk(val) {
            const slider = document.getElementById('inputRiskSlider');
            if (slider) {
                slider.value = val;
                const label = document.getElementById('labelRiskPercent');
                if (label) label.textContent = `${val}%`;
                this.calculate();
            }
        },

        setCapital(val) {
            const input = document.getElementById('inputCapital');
            if (input) {
                input.value = val;
                this.calculate();
            }
        },

        renderLeverageTable(capital, slPercent, positionSize) {
            const leverages = [1, 2, 5, 10, 20, 50, 100, 125];
            const tbody = document.getElementById('leverageTableBody');
            if (!tbody) return;

            let html = '';
            leverages.forEach(lev => {
                const marginReq = positionSize / lev;
                const liqDistance = 100 / lev;

                // Risk Status
                let status = '<span class="text-emerald-400 font-bold">Safe</span>';
                let statusClass = "text-emerald-400";

                if (slPercent >= liqDistance) {
                    status = '<span class="text-rose-500 font-black animate-pulse">LIQUIDATION RISK</span>';
                    statusClass = "text-rose-500";
                } else if (slPercent >= liqDistance * 0.8) {
                    status = '<span class="text-amber-500 font-bold">High Risk</span>';
                    statusClass = "text-amber-500";
                }

                // If Margin Req > Capital, impossible trade
                if (marginReq > capital) {
                    status = '<span class="text-slate-500 font-bold">Insufficient Balance</span>';
                    statusClass = "text-slate-500";
                    // Also mute the text if impossible
                }

                html += `
                    <tr class="group hover:bg-white/5 transition-colors border-b border-slate-800/50 last:border-0">
                        <td class="px-6 py-4 font-bold text-white">${lev}x</td>
                        <td class="px-6 py-4 text-slate-400 font-mono text-xs">
                             Req. Move: <span class="${statusClass}">${liqDistance.toFixed(2)}%</span>
                        </td>
                        <td class="px-6 py-4 text-right font-mono text-slate-300">$${marginReq.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
                        <td class="px-6 py-4 text-right font-mono text-slate-300">$${positionSize.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
                        <td class="px-6 py-4 text-center text-xs uppercase tracking-wide">${status}</td>
                    </tr>
                 `;
            });
            tbody.innerHTML = html;
        }
    },

    simulator: {
        chart: null,

        trades: [],

        runSimulation() {
            const winRateInput = document.getElementById('sim-input-winrate');
            if (!winRateInput) return;
            const winRate = parseFloat(winRateInput.value) || 0;

            this.trades = [];
            for (let i = 1; i <= 100; i++) {
                this.trades.push({
                    id: i,
                    isWin: Math.random() * 100 < winRate
                });
            }

            this.calculateSimulation();
        },

        toggleTrade(index) {
            if (this.trades[index]) {
                this.trades[index].isWin = !this.trades[index].isWin;
                this.calculateSimulation();
            }
        },

        calculateSimulation() {
            const capitalInput = document.getElementById('sim-input-capital');
            const riskInput = document.getElementById('sim-input-risk');
            const rrrInput = document.getElementById('sim-input-rrr');

            if (!capitalInput || !riskInput || !rrrInput) return;

            const startCapital = parseFloat(capitalInput.value) || 0;
            const riskPercent = parseFloat(riskInput.value) || 0;
            const rrr = parseFloat(rrrInput.value) || 0;

            let currentEquity = startCapital;
            let equityCurve = [startCapital];
            let processedTrades = [];

            let maxDD = 0;
            let peak = startCapital;

            // Wipeout Analysis (Linear / Bullet Count)
            let bullets = "Infinity";
            if (riskPercent > 0) {
                bullets = Math.floor(100 / riskPercent);
            }

            this.trades.forEach((t, index) => {
                const tradeStartCap = currentEquity;
                const riskAmt = currentEquity * (riskPercent / 100);
                const profitAmt = riskAmt * rrr;

                let pnl = 0;
                let outcome = 'LOSS';

                if (t.isWin) {
                    pnl = profitAmt;
                    currentEquity += profitAmt;
                    outcome = 'WIN';
                } else {
                    pnl = -riskAmt;
                    currentEquity -= riskAmt;
                }

                if (currentEquity > peak) peak = currentEquity;
                const dd = ((peak - currentEquity) / peak) * 100;
                if (dd > maxDD) maxDD = dd;

                equityCurve.push(currentEquity);
                processedTrades.push({
                    id: t.id,
                    index: index,
                    start: tradeStartCap,
                    risk: riskAmt,
                    outcome,
                    isWin: t.isWin,
                    pnl,
                    end: currentEquity
                });
            });

            // Update Stats
            const totalROI = ((currentEquity - startCapital) / startCapital) * 100;

            document.getElementById('sim-result-capital').textContent = '$' + currentEquity.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });

            const roiEl = document.getElementById('sim-result-roi');
            if (roiEl) {
                roiEl.textContent = (totalROI >= 0 ? '+' : '') + totalROI.toFixed(2) + '%';
                roiEl.className = totalROI >= 0 ? 'text-xl font-black text-emerald-500' : 'text-xl font-black text-rose-500';
            }

            const ddEl = document.getElementById('sim-result-dd');
            if (ddEl) ddEl.textContent = '-' + maxDD.toFixed(1) + '%';

            const wipeoutEl = document.getElementById('sim-wipeout-count');
            if (wipeoutEl) wipeoutEl.textContent = bullets;

            const wipeoutMsg = document.getElementById('sim-wipeout-msg');
            if (wipeoutMsg) {
                if (bullets < 20) wipeoutMsg.innerHTML = `<span class="text-rose-500 font-bold">CRITICAL WARNING:</span> High probability of ruin.`;
                else if (bullets < 50) wipeoutMsg.innerHTML = `<span class="text-amber-500 font-bold">CAUTION:</span> Moderate risk.`;
                else wipeoutMsg.innerHTML = `<span class="text-emerald-500 font-bold">SAFE:</span> conservative risk profile.`;
            }

            this.renderTable(processedTrades);
            this.renderChart(equityCurve);
        },

        _old_runSimulation() {
            // 1. Get Inputs
            const capitalInput = document.getElementById('sim-input-capital');
            const winRateInput = document.getElementById('sim-input-winrate');
            const riskInput = document.getElementById('sim-input-risk');
            const rrrInput = document.getElementById('sim-input-rrr');

            if (!capitalInput || !winRateInput || !riskInput || !rrrInput) return;

            const capital = parseFloat(capitalInput.value) || 0;
            const winRate = parseFloat(winRateInput.value) || 0;
            const risk = parseFloat(riskInput.value) || 0;
            const rrr = parseFloat(rrrInput.value) || 0;

            let currentEquity = capital;
            let equityCurve = [capital];
            let trades = [];

            const numTrades = 100;
            let maxDD = 0;
            let peak = capital;

            // 2. Wipeout Analysis (Consecutive Losses to < 10% remaining)
            // Logarithmic decay: End = Start * (1 - risk)^N
            // 0.1 = (1 - risk)^N  => N = ln(0.1) / ln(1 - risk)
            // If risk is 0, Infinity.
            let wipeoutTrades = "Infinity";
            if (risk > 0) {
                const lossMultiplier = 1 - (risk / 100);
                if (lossMultiplier < 1) {
                    // Calculate trades to lose 90% of account (down to 10%)
                    const tradesToRuin = Math.log(0.1) / Math.log(lossMultiplier);
                    wipeoutTrades = Math.ceil(tradesToRuin);
                }
            }

            // 3. Simulation Loop
            for (let i = 1; i <= numTrades; i++) {
                const isWin = Math.random() * 100 < winRate;

                const startCap = currentEquity;
                // Risk Amount (Compounding)
                const riskAmt = currentEquity * (risk / 100);
                const profitAmt = riskAmt * rrr;

                let pnl = 0;
                let outcome = 'LOSS';

                if (isWin) {
                    pnl = profitAmt;
                    currentEquity += profitAmt;
                    outcome = 'WIN';
                } else {
                    pnl = -riskAmt;
                    currentEquity -= riskAmt;
                }

                // Drawdown
                if (currentEquity > peak) peak = currentEquity;
                const dd = ((peak - currentEquity) / peak) * 100;
                if (dd > maxDD) maxDD = dd;

                equityCurve.push(currentEquity);
                trades.push({
                    id: i,
                    start: startCap,
                    risk: riskAmt,
                    outcome,
                    pnl,
                    end: currentEquity
                });
            }

            // 4. Update Stats UI
            const totalROI = ((currentEquity - capital) / capital) * 100;

            document.getElementById('sim-result-capital').textContent = '$' + currentEquity.toLocaleString(undefined, { maximumFractionDigits: 0 });

            const roiEl = document.getElementById('sim-result-roi');
            if (roiEl) {
                roiEl.textContent = (totalROI >= 0 ? '+' : '') + totalROI.toFixed(0) + '%';
                roiEl.className = totalROI >= 0 ? 'text-xl font-black text-emerald-500' : 'text-xl font-black text-rose-500';
            }

            const ddEl = document.getElementById('sim-result-dd');
            if (ddEl) ddEl.textContent = '-' + maxDD.toFixed(1) + '%';

            const wipeoutEl = document.getElementById('sim-wipeout-count');
            if (wipeoutEl) wipeoutEl.textContent = wipeoutTrades;

            const wipeoutMsg = document.getElementById('sim-wipeout-msg');
            if (wipeoutMsg) {
                if (wipeoutTrades < 20) wipeoutMsg.innerHTML = `<span class="text-rose-500 font-bold">CRITICAL WARNING:</span> High probability of ruin.`;
                else if (wipeoutTrades < 50) wipeoutMsg.innerHTML = `<span class="text-amber-500 font-bold">CAUTION:</span> Moderate risk.`;
                else wipeoutMsg.innerHTML = `<span class="text-emerald-500 font-bold">SAFE:</span> conservative risk profile.`;
            }

            // 5. Render Table
            this.renderTable(trades);

            // 6. Render Chart
            this.renderChart(equityCurve);
        },

        renderTable(trades) {
            const tbody = document.getElementById('sim-table-body');
            if (!tbody) return;

            let html = '';
            trades.forEach(t => {
                const isWin = t.isWin;
                html += `
                    <tr class="hover:bg-slate-100 dark:hover:bg-slate-800/50 transition-colors border-b border-border-light dark:border-border-dark last:border-0">
                        <td class="px-6 py-3 font-mono text-xs text-text-muted-light dark:text-text-muted-dark">${t.id}</td>
                        <td class="px-6 py-3 font-mono text-sm text-text-main-light dark:text-text-main-dark">$${t.start.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
                        <td class="px-6 py-3 font-mono text-xs text-rose-400">-$${t.risk.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
                        <td class="px-6 py-3 text-center">
                             <button onclick="app.simulator.toggleTrade(${t.index})" 
                                class="cursor-pointer hover:scale-110 active:scale-95 transition-transform text-[10px] font-bold px-2 py-1 rounded shadow-sm ${isWin ? 'bg-emerald-500 text-white' : 'bg-rose-500 text-white'}">
                                ${t.outcome}
                            </button>
                        </td>
                        <td class="px-6 py-3 text-right font-mono text-sm font-bold ${isWin ? 'text-emerald-500' : 'text-rose-500'}">
                            ${isWin ? '+' : ''}$${t.pnl.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
                        </td>
                        <td class="px-6 py-3 text-right font-mono text-sm font-bold text-text-main-light dark:text-text-main-dark">$${t.end.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
                    </tr>
                `;
            });
            tbody.innerHTML = html;
        },

        renderChart(data) {
            const ctx = document.getElementById('chart-simulator')?.getContext('2d');
            if (!ctx) return;

            if (this.chart) this.chart.destroy();

            // Gradient
            const gradient = ctx.createLinearGradient(0, 0, 0, 400);
            gradient.addColorStop(0, 'rgba(66, 133, 244, 0.5)'); // Google Blue
            gradient.addColorStop(1, 'rgba(66, 133, 244, 0)');

            this.chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.map((_, i) => i),
                    datasets: [{
                        label: 'Equity',
                        data: data,
                        borderColor: '#4285F4',
                        backgroundColor: gradient,
                        borderWidth: 2,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                            backgroundColor: 'rgba(15, 23, 42, 0.9)',
                            titleColor: '#94a3b8',
                            bodyColor: '#fff',
                            borderColor: 'rgba(255,255,255,0.1)',
                            borderWidth: 1
                        }
                    },
                    scales: {
                        x: { display: false },
                        y: {
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: { color: '#64748b' }
                        }
                    },
                    interaction: {
                        mode: 'nearest',
                        axis: 'x',
                        intersect: false
                    },
                    animation: {
                        duration: 0 // Instant update for standard feel
                    }
                }
            });
        }
    },

    // --- HABIT TRACKER ---

    saveHabits() {
        const habitsKey = this.getStorageKey('habits');
        if (habitsKey) SafeStorage.set(habitsKey, JSON.stringify(this.habits));

        const badHabitsKey = this.getStorageKey('badHabits');
        if (badHabitsKey) SafeStorage.set(badHabitsKey, JSON.stringify(this.badHabits));

        const habitLogsKey = this.getStorageKey('habitLogs');
        if (habitLogsKey) SafeStorage.set(habitLogsKey, JSON.stringify(this.habitLogs));

        // Auto-save to cloud
        CloudStorage.saveFullBackup(this);
    },

    renderHabits() {
        const listCues = document.getElementById('list-cues');
        const listCravings = document.getElementById('list-cravings');
        const listEase = document.getElementById('list-ease');
        const listRewards = document.getElementById('list-rewards');

        // Support both old and new container IDs (Reverted design uses habit-grid)
        const checklist = document.getElementById('habit-grid') || document.getElementById('habit-checklist-container');

        if (!checklist) return;

        // Clear Lists if they exist
        if (listCues) listCues.innerHTML = '';
        if (listCravings) listCravings.innerHTML = '';
        if (listEase) listEase.innerHTML = '';
        if (listRewards) listRewards.innerHTML = '';

        checklist.innerHTML = '';

        // Get Today's Log
        const today = new Date().toISOString().split('T')[0];
        const log = this.habitLogs[today] || [];

        this.habits.forEach(habit => {
            // Populate Atomic Lists (Conditional)
            if (listCues && habit.cue) listCues.innerHTML += `<li>${habit.cue}</li>`;
            if (listCravings && habit.craving) listCravings.innerHTML += `<li>${habit.craving}</li>`;
            if (listEase && habit.name) listEase.innerHTML += `<li>Reduce friction for: <strong>${habit.name}</strong></li>`;
            if (listRewards && habit.reward) listRewards.innerHTML += `<li>${habit.reward}</li>`;

            // Calculate Stats for this habit
            let daysAccomplished = 0;
            Object.values(this.habitLogs).forEach(dayLogs => {
                if (dayLogs.includes(habit.id)) daysAccomplished++;
            });
            const target = habit.target || 66;

            // Populate Checklist
            const isCompleted = log.includes(habit.id);
            checklist.innerHTML += `
                <div class="flex flex-col p-4 rounded-xl border ${isCompleted ? 'border-emerald-500/50 bg-emerald-500/10' : 'border-border-light dark:border-border-dark bg-surface-light dark:bg-surface-dark'} transition-all shadow-sm group relative">
                    
                    <div class="flex items-center justify-between mb-3">
                         <div class="flex items-center gap-3 cursor-pointer" onclick="app.toggleHabit(${habit.id})">
                            <div class="w-6 h-6 rounded-full border-2 ${isCompleted ? 'bg-emerald-500 border-emerald-500' : 'border-slate-400 group-hover:border-emerald-400'} flex items-center justify-center transition-all shrink-0">
                                 ${isCompleted ? '<span class="material-symbols-outlined text-white text-sm">check</span>' : ''}
                            </div>
                            <span class="${isCompleted ? 'line-through text-slate-500' : 'font-medium text-text-main-light dark:text-text-main-dark'}">${habit.name}</span>
                        </div>
                        
                        <!-- Actions -->
                        <div class="flex items-center gap-1 opacity-100 md:opacity-0 group-hover:opacity-100 transition-opacity">
                            <button onclick="event.stopPropagation(); app.editHabit(${habit.id})" class="p-1.5 text-slate-400 hover:text-primary hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" title="Edit">
                                <span class="material-symbols-outlined text-[18px]">edit</span>
                            </button>
                            <button onclick="event.stopPropagation(); app.deleteHabit(${habit.id})" class="p-1.5 text-slate-400 hover:text-loss hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" title="Delete">
                                <span class="material-symbols-outlined text-[18px]">delete</span>
                            </button>
                        </div>
                    </div>

                    <div class="flex items-center justify-between text-xs text-text-muted-light dark:text-text-muted-dark">
                        <div class="flex gap-2">
                             ${habit.cue ? `<span class="bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded">${habit.cue}</span>` : ''}
                        </div>
                        <div class="font-bold flex items-center gap-1">
                             <span class="${daysAccomplished >= target ? 'text-emerald-500' : ''}">${daysAccomplished}</span> 
                             <span class="opacity-50">/</span> 
                             <span>${target} Days</span>
                        </div>
                    </div>
                </div>
            `;
        });

        if (this.habits.length === 0) {
            const emptyState = `
                <div class="col-span-full p-12 text-center border-2 border-dashed border-border-light dark:border-border-dark rounded-xl">
                    <span class="material-symbols-outlined text-4xl text-slate-600 mb-2">playlist_add_check</span>
                    <p class="text-slate-500 font-medium">No habits defined yet.</p>
                    <button onclick="app.addHabitModal()" class="mt-4 text-emerald-500 font-bold text-sm hover:underline">Create your first protocol</button>
                </div>`;
            checklist.innerHTML = emptyState;
        }

        // Render Bad Habits
        const badList = document.getElementById('bad-habit-list');
        if (badList) {
            badList.innerHTML = '';
            this.badHabits.forEach((bh, index) => {
                badList.innerHTML += `
                    <div class="flex justify-between items-center p-3 bg-rose-500/5 border border-rose-500/10 rounded-xl">
                        <div>
                            <p class="font-bold text-rose-400 text-sm">${bh.name}</p>
                            <p class="text-[10px] text-rose-300/70">Consequence: ${bh.consequence}</p>
                        </div>
                        <button onclick="app.removeBadHabit(${index})" class="text-rose-500 hover:bg-rose-500/10 p-1 rounded transition-colors material-symbols-outlined text-sm">delete</button>
                    </div>
                `;
            });
            if (this.badHabits.length === 0) {
                badList.innerHTML = '<div class="text-center py-4"><p class="text-xs text-slate-500">No bad habits tracked yet.</p></div>';
            }
        }

        // Update Streak Display
        this.calculateStreak();
    },

    toggleHabit(id) {
        const today = new Date().toISOString().split('T')[0];
        if (!this.habitLogs[today]) this.habitLogs[today] = [];

        const index = this.habitLogs[today].indexOf(id);
        if (index === -1) {
            this.habitLogs[today].push(id);
        } else {
            this.habitLogs[today].splice(index, 1);
        }

        this.saveHabits();
        this.renderHabits();
    },

    calculateStreak() {
        const sortedDates = Object.keys(this.habitLogs).sort((a, b) => new Date(b) - new Date(a));
        let streak = 0;
        let perfectDays = 0;

        // Calculate Perfect Days (All active habits completed)
        // Note: This matches current active habits. If habits changed over time, this is an approximation.
        Object.keys(this.habitLogs).forEach(date => {
            const completedIds = this.habitLogs[date] || [];
            // Check if all CURRENT habits were done. 
            // Only count if we actually have habits.
            if (this.habits.length > 0 && completedIds.length >= this.habits.length) {
                // intersection check to be sure (optional, but robust)
                const allDone = this.habits.every(h => completedIds.includes(h.id));
                if (allDone) perfectDays++;
            }
        });

        if (sortedDates.length === 0) {
            this.habitStreak = 0;
        } else {
            // Check if today is done, if not, check yesterday for streak continuation
            const today = new Date().toISOString().split('T')[0];
            const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];

            let currentDate = today;
            // If today has no logs, start checking from yesterday for the streak
            if (!this.habitLogs[today] || this.habitLogs[today].length === 0) {
                currentDate = yesterday;
            }

            // Iterate backwards
            while (true) {
                if (this.habitLogs[currentDate] && this.habitLogs[currentDate].length > 0) {
                    streak++;
                    const prev = new Date(currentDate);
                    prev.setDate(prev.getDate() - 1);
                    currentDate = prev.toISOString().split('T')[0];
                } else {
                    break;
                }
            }
            this.habitStreak = streak;
        }

        // Update DOM Elements
        const activeCountEl = document.getElementById('stat-active-count');
        const perfectDaysEl = document.getElementById('stat-perfect-days');
        const streakEl = document.getElementById('stat-global-streak');
        const streakEl2 = document.getElementById('habit-streak-count'); // The one in the right col

        if (activeCountEl) activeCountEl.textContent = this.habits.length;
        if (perfectDaysEl) perfectDaysEl.textContent = perfectDays;
        if (streakEl) streakEl.textContent = streak;
        if (streakEl2) streakEl2.textContent = streak;
    },

    addHabitModal() {
        document.getElementById('modal-add-habit').classList.remove('hidden');
    },

    saveNewHabit() {
        const form = document.getElementById('form-add-habit');
        const formData = new FormData(form);
        const name = formData.get('habit_name');
        const id = formData.get('habit_id');

        if (!name) return;

        const habitData = {
            name: name,
            target: parseInt(formData.get('habit_target') || 66),
            cue: formData.get('habit_cue'),
            craving: formData.get('habit_craving'),
            reward: formData.get('habit_reward')
        };

        if (id) {
            // Edit existing
            const index = this.habits.findIndex(h => h.id == id);
            if (index !== -1) {
                this.habits[index] = { ...this.habits[index], ...habitData };
            }
        } else {
            // Create new
            this.habits.push({
                id: Date.now(),
                ...habitData
            });
        }

        this.saveHabits();

        document.getElementById('modal-add-habit').classList.add('hidden');
        form.reset();
        // Reset hidden id
        form.querySelector('[name="habit_id"]').value = '';
        this.renderHabits();
    },

    editHabit(id) {
        const habit = this.habits.find(h => h.id === id);
        if (!habit) return;

        const form = document.getElementById('form-add-habit');
        form.querySelector('[name="habit_id"]').value = habit.id;
        form.querySelector('[name="habit_name"]').value = habit.name;
        form.querySelector('[name="habit_target"]').value = habit.target || 66;
        form.querySelector('[name="habit_cue"]').value = habit.cue || '';
        form.querySelector('[name="habit_craving"]').value = habit.craving || '';
        form.querySelector('[name="habit_reward"]').value = habit.reward || '';

        document.getElementById('modal-add-habit').classList.remove('hidden');
    },

    deleteHabit(id) {
        this.showConfirm("Delete this habit protocol?", () => {
            this.habits = this.habits.filter(h => h.id !== id);
            this.saveHabits();
            this.renderHabits();
        });
    },

    addBadHabitModal() {
        document.getElementById('modal-add-bad-habit').classList.remove('hidden');
    },

    saveBadHabit() {
        const form = document.getElementById('form-add-bad-habit');
        const formData = new FormData(form);
        const name = formData.get('bad_habit_name');

        if (!name) return;

        const newBH = {
            name: name,
            consequence: formData.get('bad_habit_consequence')
        };

        this.badHabits.push(newBH);
        this.saveHabits();

        document.getElementById('modal-add-bad-habit').classList.add('hidden');
        form.reset();
        this.renderHabits();
    },




    showConfirm(message, onConfirm) {
        const modal = document.getElementById('modal-confirm');
        const msgEl = document.getElementById('confirm-message');
        const btnConfirm = document.getElementById('btn-confirm-action');
        const btnCancel = document.getElementById('btn-confirm-cancel');

        if (!modal || !msgEl || !btnConfirm || !btnCancel) {
            console.error("Confirm modal elements missing!");
            if (confirm(message)) onConfirm(); // Fallback
            return;
        }

        msgEl.textContent = message;
        modal.classList.remove('hidden');

        // Cleanup previous listeners
        const close = () => {
            modal.classList.add('hidden');
            btnConfirm.onclick = null;
            btnCancel.onclick = null;
        };

        btnConfirm.onclick = () => {
            close();
            onConfirm();
        };

        btnCancel.onclick = close;
    },

    backupData() {
        // Trigger Cloud Save
        // We pass 'this' (the app object) to the CloudStorage manager
        CloudStorage.saveFullBackup(this);
    }
};

// Make app globally accessible for HTML onclick handlers
window.app = app;

// Initialize App
document.addEventListener('DOMContentLoaded', () => {
    app.init();
});
