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

// Admin API
export interface AdminUser {
    id: string;
    email: string;
    name: string;
    role: string;
    email_verified: boolean;
    totp_enabled: boolean;
    created_at: string;
    last_login?: string;
}

export interface AdminNetwork {
    id: string;
    name: string;
    cidr: string;
    owner_id?: string;
    owner_email?: string;
    node_count: number;
    created_at: string;
}

export interface SystemStats {
    total_users: number;
    verified_users: number;
    admin_users: number;
    total_networks: number;
    total_nodes: number;
    online_nodes: number;
    offline_nodes: number;
    pending_nodes: number;
    active_sessions: number;
    logins_today: number;
    registrations_today: number;
    server_version: string;
    uptime_seconds: number;
}

export interface AuditLogEntry {
    id: string;
    event_type: string;
    user_id?: string;
    user_email?: string;
    target_type?: string;
    target_id?: string;
    ip_address?: string;
    details?: Record<string, unknown>;
    created_at: string;
}

export const adminApi = {
    // Users
    listUsers: (params?: { offset?: number; limit?: number; search?: string }) => {
        const searchParams = new URLSearchParams();
        if (params?.offset) searchParams.set('offset', String(params.offset));
        if (params?.limit) searchParams.set('limit', String(params.limit));
        if (params?.search) searchParams.set('search', params.search);
        const query = searchParams.toString();
        const endpoint = query ? `/api/admin/users?${query}` : '/api/admin/users';
        return request<{ users: AdminUser[]; total: number; offset: number; limit: number }>(endpoint);
    },

    getUser: (id: string) => request<AdminUser>(`/api/admin/users/${id}`),

    updateUser: (id: string, data: { role?: string; email_verified?: boolean }) =>
        request<AdminUser>(`/api/admin/users/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        }),

    deleteUser: (id: string) => request<void>(`/api/admin/users/${id}`, { method: 'DELETE' }),

    // Networks
    listNetworks: (params?: { offset?: number; limit?: number; search?: string }) => {
        const searchParams = new URLSearchParams();
        if (params?.offset) searchParams.set('offset', String(params.offset));
        if (params?.limit) searchParams.set('limit', String(params.limit));
        if (params?.search) searchParams.set('search', params.search);
        const query = searchParams.toString();
        const endpoint = query ? `/api/admin/networks?${query}` : '/api/admin/networks';
        return request<{ networks: AdminNetwork[]; total: number; offset: number; limit: number }>(endpoint);
    },

    // Stats
    getStats: () => request<SystemStats>('/api/admin/stats'),

    // Audit Log
    listAuditLog: (params?: { offset?: number; limit?: number; event_type?: string; user_id?: string }) => {
        const searchParams = new URLSearchParams();
        if (params?.offset) searchParams.set('offset', String(params.offset));
        if (params?.limit) searchParams.set('limit', String(params.limit));
        if (params?.event_type) searchParams.set('event_type', params.event_type);
        if (params?.user_id) searchParams.set('user_id', params.user_id);
        const query = searchParams.toString();
        const endpoint = query ? `/api/admin/audit-log?${query}` : '/api/admin/audit-log';
        return request<{ entries: AuditLogEntry[]; total: number; offset: number; limit: number }>(endpoint);
    },
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
