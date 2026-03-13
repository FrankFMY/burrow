const STORAGE_KEY = 'burrow_admin_servers';

export interface AdminServer {
	name: string;
	url: string;
	isActive: boolean;
}

function load(): AdminServer[] {
	try {
		const raw = localStorage.getItem(STORAGE_KEY);
		if (!raw) return [];
		const parsed = JSON.parse(raw);
		if (!Array.isArray(parsed)) return [];
		return parsed.filter(
			(s: any) =>
				typeof s.name === 'string' &&
				typeof s.url === 'string' &&
				typeof s.isActive === 'boolean',
		);
	} catch {
		return [];
	}
}

function save(servers: AdminServer[]): void {
	localStorage.setItem(STORAGE_KEY, JSON.stringify(servers));
}

function normalizeUrl(url: string): string {
	return url.replace(/\/+$/, '');
}

export function getServers(): AdminServer[] {
	return load();
}

export function addServer(name: string, url: string): void {
	const trimmedName = name.trim();
	const trimmedUrl = normalizeUrl(url.trim());
	if (!trimmedName || !trimmedUrl) return;

	const servers = load();
	const exists = servers.some((s) => s.name === trimmedName);
	if (exists) return;

	const isFirst = servers.length === 0;
	servers.push({ name: trimmedName, url: trimmedUrl, isActive: isFirst });
	save(servers);
}

export function removeServer(name: string): void {
	let servers = load();
	const removed = servers.find((s) => s.name === name);
	servers = servers.filter((s) => s.name !== name);

	if (removed?.isActive && servers.length > 0) {
		servers[0].isActive = true;
	}

	save(servers);
}

export function setActiveServer(name: string): void {
	const servers = load();
	let found = false;
	for (const s of servers) {
		if (s.name === name) {
			s.isActive = true;
			found = true;
		} else {
			s.isActive = false;
		}
	}
	if (found) save(servers);
}

export function getActiveServer(): AdminServer | null {
	const servers = load();
	return servers.find((s) => s.isActive) ?? null;
}
