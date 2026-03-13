const API_BASE = 'http://127.0.0.1:9090';

export interface Server {
	name: string;
	address: string;
	port: number;
	sni: string;
	connected: boolean;
	protocol: string;
}

export interface TunnelStatus {
	running: boolean;
	reconnecting: boolean;
	reconnect_attempt: number;
	last_error: string;
	server: string;
	protocol: string;
	uptime: number;
	bytes_up: number;
	bytes_down: number;
	kill_switch: boolean;
	tun_mode: boolean;
}

export interface Preferences {
	tun_mode: boolean;
	kill_switch: boolean;
	auto_connect: boolean;
}

async function request(path: string, opts: RequestInit = {}): Promise<any> {
	const res = await fetch(`${API_BASE}${path}`, {
		...opts,
		headers: { 'Content-Type': 'application/json', ...opts.headers }
	});
	if (!res.ok) {
		const body = await res.json().catch(() => ({ error: res.statusText }));
		throw new Error(body.error || res.statusText);
	}
	return res.json();
}

export async function getStatus(): Promise<TunnelStatus> {
	return request('/api/status');
}

export async function connect(server?: string, killSwitch?: boolean, tunMode: boolean = true): Promise<void> {
	return request('/api/connect', {
		method: 'POST',
		body: JSON.stringify({ server, kill_switch: killSwitch, tun_mode: tunMode })
	});
}

export async function disconnect(): Promise<void> {
	return request('/api/disconnect', { method: 'POST' });
}

export async function getServers(): Promise<Server[]> {
	return request('/api/servers');
}

export async function addServer(inviteLink: string): Promise<Server> {
	return request('/api/servers', {
		method: 'POST',
		body: JSON.stringify({ invite: inviteLink })
	});
}

export async function removeServer(name: string): Promise<void> {
	return request(`/api/servers/${encodeURIComponent(name)}`, {
		method: 'DELETE'
	});
}

export async function getPreferences(): Promise<Preferences> {
	return request('/api/preferences');
}

export async function setPreferences(prefs: Partial<Preferences>): Promise<Preferences> {
	return request('/api/preferences', {
		method: 'PUT',
		body: JSON.stringify(prefs)
	});
}

export async function waitForDaemon(maxRetries = 15, intervalMs = 500): Promise<boolean> {
	for (let i = 0; i < maxRetries; i++) {
		try {
			await getStatus();
			return true;
		} catch {
			await new Promise(r => setTimeout(r, intervalMs));
		}
	}
	return false;
}

export function formatBytes(bytes: number): string {
	if (!bytes || bytes <= 0 || !isFinite(bytes)) return '0 B';
	const units = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
	return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

export function formatDuration(seconds: number): string {
	if (!seconds) return '0s';
	const h = Math.floor(seconds / 3600);
	const m = Math.floor((seconds % 3600) / 60);
	const s = seconds % 60;
	if (h > 0) return `${h}h ${m}m`;
	if (m > 0) return `${m}m ${s}s`;
	return `${s}s`;
}
