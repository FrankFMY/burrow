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

function createAuthStore() {
    const initialToken = browser ? localStorage.getItem(TOKEN_KEY) : null;

    const { subscribe, set, update } = writable<AuthState>({
        user: null,
        token: initialToken,
        loading: !!initialToken,
    });

    return {
        subscribe,

        setAuth: (token: string, user: User) => {
            if (browser) {
                localStorage.setItem(TOKEN_KEY, token);
            }
            set({ user, token, loading: false });
        },

        logout: () => {
            if (browser) {
                localStorage.removeItem(TOKEN_KEY);
            }
            set({ user: null, token: null, loading: false });
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
