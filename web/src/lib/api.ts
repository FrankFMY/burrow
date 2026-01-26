import { browser } from '$app/environment';
import { auth } from './stores/auth';
import { get } from 'svelte/store';

// Use environment variable in production, empty string for dev proxy
const API_BASE = browser ? (import.meta.env.VITE_API_URL || '') : '';

interface RequestOptions extends RequestInit {
    skipAuth?: boolean;
}

class ApiError extends Error {
    constructor(public status: number, message: string) {
        super(message);
        this.name = 'ApiError';
    }
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const { skipAuth, ...fetchOptions } = options;
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...(fetchOptions.headers as Record<string, string> || {}),
    };

    if (!skipAuth) {
        const { token } = get(auth);
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...fetchOptions,
        headers,
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));
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

    me: () =>
        request<{ id: string; email: string; name: string; role: string }>('/api/auth/me'),

    listApiKeys: () =>
        request<{ id: string; name: string; created_at: string; last_used?: string }[]>(
            '/api/auth/api-keys'
        ),

    createApiKey: (name: string) =>
        request<{ id: string; name: string; key: string; created_at: string }>(
            '/api/auth/api-keys',
            { method: 'POST', body: JSON.stringify({ name }) }
        ),

    revokeApiKey: (id: string) =>
        request<void>(`/api/auth/api-keys/${id}`, { method: 'DELETE' }),

    // 2FA
    totpStatus: () =>
        request<{ enabled: boolean; verified: boolean }>('/api/auth/totp'),

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
};

// Networks API
export const networksApi = {
    list: () =>
        request<{ id: string; name: string; cidr: string; created_at: string }[]>('/api/networks'),

    get: (id: string) =>
        request<{ id: string; name: string; cidr: string; created_at: string }>(`/api/networks/${id}`),

    create: (data: { name: string; cidr?: string }) =>
        request<{ id: string; name: string; cidr: string; created_at: string }>(
            '/api/networks',
            { method: 'POST', body: JSON.stringify(data) }
        ),

    delete: (id: string) =>
        request<void>(`/api/networks/${id}`, { method: 'DELETE' }),

    listNodes: (networkId: string) =>
        request<{
            id: string;
            name: string;
            public_key: string;
            mesh_ip: string;
            endpoint?: string;
            status: string;
            created_at: string;
            last_seen?: string;
        }[]>(`/api/networks/${networkId}/nodes`),

    createInvite: (networkId: string) =>
        request<{ code: string; expires_at: string }>(
            `/api/networks/${networkId}/invite`,
            { method: 'POST' }
        ),
};

export { ApiError };
