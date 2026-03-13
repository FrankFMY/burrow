const API_BASE = '/api';

function getToken(): string | null {
	return localStorage.getItem('burrow_token');
}

export function setToken(token: string) {
	localStorage.setItem('burrow_token', token);
}

export function clearToken() {
	localStorage.removeItem('burrow_token');
}

export function isAuthenticated(): boolean {
	return !!getToken();
}

async function request(path: string, options: RequestInit = {}): Promise<any> {
	const token = getToken();
	const headers: Record<string, string> = {
		'Content-Type': 'application/json',
		...(options.headers as Record<string, string> || {})
	};
	if (token) headers['Authorization'] = `Bearer ${token}`;

	const resp = await fetch(`${API_BASE}${path}`, { ...options, headers });
	if (resp.status === 401) {
		clearToken();
		window.location.href = '/admin/login';
		throw new Error('Unauthorized');
	}
	if (!resp.ok) {
		const body = await resp.json().catch(() => ({ error: resp.statusText }));
		throw new Error(body.error || resp.statusText);
	}
	return resp.json();
}

export async function login(password: string) {
	const resp = await fetch(`${API_BASE}/auth/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ password })
	});
	if (!resp.ok) throw new Error('Invalid password');
	const data = await resp.json();
	setToken(data.token);
	return data;
}

export async function getStats() {
	return request('/stats');
}

export async function getClients() {
	return request('/clients');
}

export async function getClient(id: string) {
	return request(`/clients/${id}`);
}

export async function revokeClient(id: string) {
	return request(`/clients/${id}`, { method: 'DELETE' });
}

export async function getInvites() {
	return request('/invites');
}

export async function createInvite(name: string, expiresIn?: string) {
	const body: Record<string, string> = { name };
	if (expiresIn) body.expires_in = expiresIn;
	return request('/invites', {
		method: 'POST',
		body: JSON.stringify(body)
	});
}

export async function revokeInvite(id: string) {
	return request(`/invites/${id}`, { method: 'DELETE' });
}

export async function getConfig() {
	return request('/config');
}

export function formatBytes(bytes: number): string {
	if (!bytes || bytes <= 0) return '0 B';
	const k = 1024;
	const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export function formatDate(dateStr: string): string {
	if (!dateStr) return 'Never';
	return new Date(dateStr).toLocaleDateString('en-US', {
		month: 'short', day: 'numeric', year: 'numeric',
		hour: '2-digit', minute: '2-digit'
	});
}
