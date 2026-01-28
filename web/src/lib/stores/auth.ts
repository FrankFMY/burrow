import { derived, writable } from 'svelte/store';
import { browser } from '$app/environment';

interface User {
    id: string;
    email: string;
    name: string;
    role: string;
}

interface AuthState {
    user: User | null;
    token: string | null;
    loading: boolean;
}

const TOKEN_KEY = 'burrow_token';

// API base URL for logout endpoint
const API_BASE = browser ? import.meta.env.VITE_API_URL || '' : '';

function createAuthStore() {
    const initialToken = browser ? localStorage.getItem(TOKEN_KEY) : null;

    const { subscribe, set, update } = writable<AuthState>({
        user: null,
        token: initialToken,
        loading: !!initialToken,
    });

    // Clear local state (sync)
    const clearLocalState = () => {
        if (browser) {
            localStorage.removeItem(TOKEN_KEY);
        }
        set({ user: null, token: null, loading: false });
    };

    return {
        subscribe,

        setAuth: (token: string, user: User) => {
            if (browser) {
                localStorage.setItem(TOKEN_KEY, token);
            }
            set({ user, token, loading: false });
        },

        // Sync logout - clears local state only (used for 401 auto-logout)
        logout: clearLocalState,

        // Async logout - calls API to clear httpOnly cookie, then clears local state
        logoutAsync: async () => {
            if (browser) {
                try {
                    // Call API to clear the httpOnly cookie
                    await fetch(`${API_BASE}/api/auth/logout`, {
                        method: 'POST',
                        credentials: 'include',
                    });
                } catch {
                    // Ignore errors - we still want to clear local state
                }
            }
            clearLocalState();
        },

        setLoading: (loading: boolean) => {
            update((state) => ({ ...state, loading }));
        },

        setUser: (user: User) => {
            update((state) => ({ ...state, user, loading: false }));
        },
    };
}

export const auth = createAuthStore();
export const isAuthenticated = derived(auth, ($auth) => !!$auth.token);
export const isAdmin = derived(auth, ($auth) => $auth.user?.role === 'admin');
