<script lang="ts">
	import { onMount } from 'svelte';
	import { getServers, addServer, removeServer, setActiveServer, type AdminServer } from '$lib/servers';
	import { checkHealth } from '$lib/api';

	let servers = $state<AdminServer[]>([]);
	let health = $state<Record<string, boolean | null>>({});
	let newName = $state('');
	let newUrl = $state('');
	let formError = $state('');

	function reload() {
		servers = getServers();
	}

	onMount(() => {
		reload();
		refreshHealth();
	});

	async function refreshHealth() {
		const current = getServers();
		const results: Record<string, boolean | null> = {};
		for (const s of current) {
			results[s.name] = null;
		}
		health = { ...results };

		await Promise.all(
			current.map(async (s) => {
				const ok = await checkHealth(s.url);
				health = { ...health, [s.name]: ok };
			}),
		);
	}

	function handleAdd() {
		formError = '';
		const name = newName.trim();
		const url = newUrl.trim();

		if (!name) {
			formError = 'Server name is required';
			return;
		}
		if (!url) {
			formError = 'Server URL is required';
			return;
		}
		try {
			new URL(url);
		} catch {
			formError = 'Invalid URL format';
			return;
		}
		if (servers.some((s) => s.name === name)) {
			formError = 'A server with this name already exists';
			return;
		}

		addServer(name, url);
		newName = '';
		newUrl = '';
		reload();
		refreshHealth();
	}

	function handleRemove(name: string) {
		removeServer(name);
		reload();
	}

	function handleActivate(name: string) {
		setActiveServer(name);
		reload();
	}
</script>

<h2 class="text-xl md:text-2xl font-bold mb-4 md:mb-6">Servers</h2>

<div class="space-y-4">
	<!-- Add server form -->
	<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-6 animate-in">
		<h3 class="text-sm font-medium text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-2">
			<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
				<path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4" />
			</svg>
			Add Server
		</h3>
		<form onsubmit={(e) => { e.preventDefault(); handleAdd(); }} class="space-y-3">
			<div class="flex flex-col sm:flex-row gap-3">
				<input
					type="text"
					bind:value={newName}
					placeholder="Server name (e.g. US-East)"
					class="flex-1 bg-[var(--bg-primary)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--accent)] transition-colors"
				/>
				<input
					type="text"
					bind:value={newUrl}
					placeholder="URL (e.g. https://vpn1.example.com:8080)"
					class="flex-[2] bg-[var(--bg-primary)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--accent)] transition-colors"
				/>
				<button
					type="submit"
					class="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity cursor-pointer shrink-0"
				>
					Add
				</button>
			</div>
			{#if formError}
				<p class="text-sm text-[var(--danger)]">{formError}</p>
			{/if}
		</form>
	</div>

	<!-- Server list -->
	<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-6 animate-in" style="animation-delay: 0.1s; animation-fill-mode: both">
		<div class="flex items-center justify-between mb-4">
			<h3 class="text-sm font-medium text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-2">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
				</svg>
				Configured Servers
			</h3>
			<button
				onclick={refreshHealth}
				class="text-xs text-[var(--text-secondary)] hover:text-[var(--accent)] transition-colors cursor-pointer flex items-center gap-1"
			>
				<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
				</svg>
				Refresh
			</button>
		</div>

		{#if servers.length === 0}
			<div class="text-center py-8 text-[var(--text-secondary)] text-sm">
				<svg class="w-10 h-10 mx-auto mb-3 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
					<path stroke-linecap="round" stroke-linejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
				</svg>
				<p>No servers configured.</p>
				<p class="mt-1 text-xs opacity-70">Add a server above to manage multiple Burrow instances.</p>
				<p class="mt-1 text-xs opacity-70">Without any servers configured, the dashboard connects to the local API.</p>
			</div>
		{:else}
			<div class="space-y-2">
				{#each servers as server}
					<div
						class="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 p-3 rounded-lg border transition-colors"
						class:border-[var(--accent)]/30={server.isActive}
						class:bg-[var(--accent)]/5={server.isActive}
						class:border-[var(--border)]={!server.isActive}
					>
						<!-- Health dot + name -->
						<div class="flex items-center gap-2.5 min-w-0 flex-1">
							{#if health[server.name] === null || health[server.name] === undefined}
								<div class="w-2.5 h-2.5 rounded-full bg-gray-500 shrink-0 animate-pulse" title="Checking..."></div>
							{:else if health[server.name]}
								<div class="w-2.5 h-2.5 rounded-full bg-green-500 shrink-0" title="Online"></div>
							{:else}
								<div class="w-2.5 h-2.5 rounded-full bg-red-500 shrink-0" title="Offline"></div>
							{/if}
							<div class="min-w-0">
								<div class="font-medium text-sm truncate flex items-center gap-2">
									{server.name}
									{#if server.isActive}
										<span class="text-[10px] font-semibold uppercase tracking-wider text-[var(--accent)] bg-[var(--accent)]/10 px-1.5 py-0.5 rounded">active</span>
									{/if}
								</div>
								<div class="text-xs text-[var(--text-secondary)] font-mono truncate">{server.url}</div>
							</div>
						</div>

						<!-- Actions -->
						<div class="flex items-center gap-2 shrink-0 sm:ml-auto">
							{#if !server.isActive}
								<button
									onclick={() => handleActivate(server.name)}
									class="px-3 py-1.5 text-xs font-medium bg-[var(--accent)]/10 text-[var(--accent)] rounded-lg hover:bg-[var(--accent)]/20 transition-colors cursor-pointer"
								>
									Switch
								</button>
							{/if}
							<button
								onclick={() => handleRemove(server.name)}
								class="px-3 py-1.5 text-xs font-medium text-[var(--danger)] bg-[var(--danger)]/10 rounded-lg hover:bg-[var(--danger)]/20 transition-colors cursor-pointer"
							>
								Remove
							</button>
						</div>
					</div>
				{/each}
			</div>
		{/if}
	</div>

	<!-- Info -->
	<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-6 animate-in" style="animation-delay: 0.2s; animation-fill-mode: both">
		<h3 class="text-sm font-medium text-[var(--text-secondary)] uppercase tracking-wider mb-3 flex items-center gap-2">
			<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
				<path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
			</svg>
			How it works
		</h3>
		<div class="text-sm text-[var(--text-secondary)] space-y-2">
			<p>Each Burrow server is independent. This dashboard connects to <strong>one server at a time</strong>.</p>
			<p>When you switch servers, all dashboard pages (clients, invites, settings) will show data from the active server.</p>
			<p>Server configurations are stored locally in your browser.</p>
		</div>
	</div>
</div>
