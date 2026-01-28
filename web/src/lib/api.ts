import { get } from 'svelte/store';
import { browser } from '$app/environment';
import { auth } from './stores/auth';

// Use environment variable in production, empty string for dev proxy
const API_BASE = browser ? import.meta.env.VITE_API_URL || '' : '';

interface RequestOptions extends RequestInit {
    skipAuth?: boolean;
}

class ApiError extends Error {
    constructor(
        public status: number,
        message: string
    ) {
        super(message);
        this.name = 'ApiError';
    }
}

// Track if we're currently refreshing to avoid infinite loops
let isRefreshing = false;

async function tryRefreshToken(): Promise<boolean> {
    if (isRefreshing) return false;

    isRefreshing = true;
    try {
        const response = await fetch(`${API_BASE}/api/auth/refresh`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
        });

        if (response.ok) {
            const data = await response.json();
            auth.setAuth(data.token, data.user);
            return true;
        }
        return false;
    } catch {
        return false;
    } finally {
        isRefreshing = false;
    }
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const { skipAuth, ...fetchOptions } = options;
    const customHeaders = fetchOptions.headers as Record<string, string> | undefined;
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...customHeaders,
    };

    if (!skipAuth) {
        const { token } = get(auth);
        if (token) {
            headers.Authorization = `Bearer ${token}`;
        }
    }

    let response = await fetch(`${API_BASE}${endpoint}`, {
        ...fetchOptions,
        headers,
        credentials: 'include', // Send cookies for httpOnly auth
    });

    // Try to refresh token on 401 (unless already trying to refresh or skipAuth)
    if (response.status === 401 && !skipAuth && browser && !isRefreshing) {
        const refreshed = await tryRefreshToken();
        if (refreshed) {
            // Retry the original request with new token
            const { token } = get(auth);
            if (token) {
                headers.Authorization = `Bearer ${token}`;
            }
            response = await fetch(`${API_BASE}${endpoint}`, {
                ...fetchOptions,
                headers,
                credentials: 'include',
            });
        }
    }

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));

        // Auto-logout on 401 (expired/invalid token) for authenticated requests
        if (response.status === 401 && !skipAuth && browser) {
            auth.logout();
            // Redirect to login page
            globalThis.location.href = '/login';
        }

        throw new ApiError(response.status, error.error || error.message || 'Request failed');
    }

    if (response.status === 204) {
        return null as T;
    }

    return response.json();
}

// Auth API
export const authApi = {
    register: (data: { email: string; password: string; name: string }) =>
        request<{ token: string; user: { id: string; email: string; name: string; role: string } }>(
            '/api/auth/register',
            { method: 'POST', body: JSON.stringify(data), skipAuth: true }
        ),

    login: (data: { email: string; password: string; totp_code?: string }) =>
        request<{ token: string; user: { id: string; email: string; name: string; role: string } }>(
            '/api/auth/login',
            { method: 'POST', body: JSON.stringify(data), skipAuth: true }
        ),

    me: () => request<{ id: string; email: string; name: string; role: string }>('/api/auth/me'),

    logout: () => request<void>('/api/auth/logout', { method: 'POST' }),

    listApiKeys: () =>
        request<{ id: string; name: string; created_at: string; last_used?: string }[]>(
            '/api/auth/api-keys'
        ),

    createApiKey: (name: string) =>
        request<{ id: string; name: string; key: string; created_at: string }>(
            '/api/auth/api-keys',
            { method: 'POST', body: JSON.stringify({ name }) }
        ),

    revokeApiKey: (id: string) => request<void>(`/api/auth/api-keys/${id}`, { method: 'DELETE' }),

    // 2FA
    totpStatus: () => request<{ enabled: boolean; verified: boolean }>('/api/auth/totp'),

    enableTotp: () =>
        request<{
            secret: string;
            qr_code: string;
            otpauth_uri: string;
            backup_codes: string[];
        }>('/api/auth/totp/enable', { method: 'POST' }),

    verifyTotp: (code: string) =>
        request<void>('/api/auth/totp/verify', {
            method: 'POST',
            body: JSON.stringify({ code }),
        }),

    disableTotp: (code: string) =>
        request<void>('/api/auth/totp/disable', {
            method: 'POST',
            body: JSON.stringify({ code }),
        }),

    // Email verification
    verifyEmail: (token: string) =>
        request<{ message: string }>('/api/auth/verify-email', {
            method: 'POST',
            body: JSON.stringify({ token }),
            skipAuth: true,
        }),

    resendVerification: (email: string) =>
        request<{ message: string }>('/api/auth/resend-verification', {
            method: 'POST',
            body: JSON.stringify({ email }),
            skipAuth: true,
        }),

    emailStatus: () => request<{ verified: boolean }>('/api/auth/email-status'),

    // Password reset
    forgotPassword: (email: string) =>
        request<{ message: string }>('/api/auth/forgot-password', {
            method: 'POST',
            body: JSON.stringify({ email }),
            skipAuth: true,
        }),

    resetPassword: (token: string, newPassword: string) =>
        request<{ message: string }>('/api/auth/reset-password', {
            method: 'POST',
            body: JSON.stringify({ token, new_password: newPassword }),
            skipAuth: true,
        }),

    // Token refresh
    refreshToken: () =>
        request<{ token: string; user: { id: string; email: string; name: string; role: string }; expires_in: number }>(
            '/api/auth/refresh',
            { method: 'POST', skipAuth: true }
        ),
};

// Networks API
export const networksApi = {
    list: () =>
        request<{ id: string; name: string; cidr: string; created_at: string }[]>('/api/networks'),

    get: (id: string) =>
        request<{ id: string; name: string; cidr: string; created_at: string }>(
            `/api/networks/${id}`
        ),

    create: (data: { name: string; cidr?: string }) =>
        request<{ id: string; name: string; cidr: string; created_at: string }>('/api/networks', {
            method: 'POST',
            body: JSON.stringify(data),
        }),

    delete: (id: string) => request<void>(`/api/networks/${id}`, { method: 'DELETE' }),

    listNodes: (networkId: string) =>
        request<
            {
                id: string;
                name: string;
                public_key: string;
                mesh_ip: string;
                endpoint?: string;
                status: string;
                created_at: string;
                last_seen?: string;
            }[]
        >(`/api/networks/${networkId}/nodes`),

    createInvite: (networkId: string) =>
        request<{ code: string; expires_at: string }>(`/api/networks/${networkId}/invite`, {
            method: 'POST',
        }),
};

export { ApiError };

// Helper to extract error message from unknown catch value
export function getErrorMessage(error: unknown): string {
    if (error instanceof ApiError) {
        return error.message;
    }
    if (error instanceof Error) {
        return error.message;
    }
    if (typeof error === 'string') {
        return error;
    }
    return 'Unknown error';
}
