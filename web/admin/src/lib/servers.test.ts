import { describe, it, expect, beforeEach } from 'vitest';
import {
	getServers,
	addServer,
	removeServer,
	setActiveServer,
	getActiveServer,
} from './servers';

const STORAGE_KEY = 'burrow_admin_servers';

beforeEach(() => {
	localStorage.clear();
});

describe('getServers', () => {
	it('returns empty array when nothing stored', () => {
		expect(getServers()).toEqual([]);
	});

	it('returns empty array for invalid JSON', () => {
		localStorage.setItem(STORAGE_KEY, 'not-json');
		expect(getServers()).toEqual([]);
	});

	it('returns empty array for non-array JSON', () => {
		localStorage.setItem(STORAGE_KEY, '{"name":"test"}');
		expect(getServers()).toEqual([]);
	});

	it('filters out malformed entries', () => {
		localStorage.setItem(STORAGE_KEY, JSON.stringify([
			{ name: 'good', url: 'https://a.com', isActive: true },
			{ name: 123, url: 'bad', isActive: false },
			{ noname: 'x', url: 'y', isActive: false },
		]));
		const servers = getServers();
		expect(servers).toHaveLength(1);
		expect(servers[0].name).toBe('good');
	});
});

describe('addServer', () => {
	it('adds a server to empty list and marks it active', () => {
		addServer('US-East', 'https://us-east.example.com:8080');
		const servers = getServers();
		expect(servers).toHaveLength(1);
		expect(servers[0]).toEqual({
			name: 'US-East',
			url: 'https://us-east.example.com:8080',
			isActive: true,
		});
	});

	it('second server is not active by default', () => {
		addServer('US-East', 'https://us-east.example.com');
		addServer('EU-West', 'https://eu-west.example.com');
		const servers = getServers();
		expect(servers).toHaveLength(2);
		expect(servers[0].isActive).toBe(true);
		expect(servers[1].isActive).toBe(false);
	});

	it('ignores empty name or url', () => {
		addServer('', 'https://test.com');
		addServer('test', '');
		addServer('  ', 'https://test.com');
		addServer('test', '   ');
		expect(getServers()).toEqual([]);
	});

	it('does not add duplicate names', () => {
		addServer('US-East', 'https://us-east.example.com');
		addServer('US-East', 'https://different-url.example.com');
		expect(getServers()).toHaveLength(1);
	});

	it('strips trailing slashes from URL', () => {
		addServer('test', 'https://example.com:8080///');
		expect(getServers()[0].url).toBe('https://example.com:8080');
	});

	it('trims whitespace from name and url', () => {
		addServer('  My Server  ', '  https://example.com  ');
		const s = getServers()[0];
		expect(s.name).toBe('My Server');
		expect(s.url).toBe('https://example.com');
	});
});

describe('removeServer', () => {
	it('removes a server by name', () => {
		addServer('A', 'https://a.com');
		addServer('B', 'https://b.com');
		removeServer('A');
		const servers = getServers();
		expect(servers).toHaveLength(1);
		expect(servers[0].name).toBe('B');
	});

	it('promotes first remaining server to active when active is removed', () => {
		addServer('A', 'https://a.com');
		addServer('B', 'https://b.com');
		addServer('C', 'https://c.com');
		removeServer('A');
		const servers = getServers();
		expect(servers[0].name).toBe('B');
		expect(servers[0].isActive).toBe(true);
	});

	it('does nothing when name not found', () => {
		addServer('A', 'https://a.com');
		removeServer('nonexistent');
		expect(getServers()).toHaveLength(1);
	});

	it('handles removing last server', () => {
		addServer('A', 'https://a.com');
		removeServer('A');
		expect(getServers()).toEqual([]);
	});
});

describe('setActiveServer', () => {
	it('sets the specified server as active and deactivates others', () => {
		addServer('A', 'https://a.com');
		addServer('B', 'https://b.com');
		addServer('C', 'https://c.com');
		setActiveServer('C');
		const servers = getServers();
		expect(servers.find((s) => s.name === 'A')!.isActive).toBe(false);
		expect(servers.find((s) => s.name === 'B')!.isActive).toBe(false);
		expect(servers.find((s) => s.name === 'C')!.isActive).toBe(true);
	});

	it('does nothing when name not found', () => {
		addServer('A', 'https://a.com');
		setActiveServer('nonexistent');
		const servers = getServers();
		expect(servers[0].isActive).toBe(true);
	});
});

describe('getActiveServer', () => {
	it('returns null when no servers configured', () => {
		expect(getActiveServer()).toBeNull();
	});

	it('returns the active server', () => {
		addServer('A', 'https://a.com');
		addServer('B', 'https://b.com');
		setActiveServer('B');
		const active = getActiveServer();
		expect(active).not.toBeNull();
		expect(active!.name).toBe('B');
		expect(active!.url).toBe('https://b.com');
	});

	it('returns first server as active after adding only one', () => {
		addServer('Solo', 'https://solo.com');
		const active = getActiveServer();
		expect(active!.name).toBe('Solo');
	});
});
