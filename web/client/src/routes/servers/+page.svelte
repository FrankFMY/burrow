<script lang="ts">
	import { getServers, addServer, removeServer, pingServer, type Server } from '$lib/api';
	import { t } from '$lib/i18n.svelte';
	import { store } from '$lib/stores.svelte';
	import { onMount } from 'svelte';

	let servers = $state<Server[]>([]);
	let inviteLink = $state('');
	let adding = $state(false);
	let error = $state('');
	let success = $state('');
	let loading = $state(true);
	let confirmingRemove = $state('');
	let latencies = $state<Record<string, number>>({});

	onMount(load);

	async function load() {
		try {
			servers = await getServers();
			pingAll();
		} catch {
			error = t('server.daemon_error');
		} finally {
			loading = false;
		}
	}

	function pingAll() {
		for (const s of servers) {
			pingServer(s.name).then(r => {
				latencies[s.name] = r.reachable ? r.latency : -1;
				latencies = latencies;
			}).catch(() => {
				latencies[s.name] = -1;
				latencies = latencies;
			});
		}
	}

	async function handleAdd(e: Event) {
		e.preventDefault();
		if (!inviteLink.trim()) return;
		adding = true;
		error = '';
		success = '';
		try {
			await addServer(inviteLink.trim());
			inviteLink = '';
			success = t('server.added');
			setTimeout(() => { success = ''; }, 3000);
			await load();
			await store.refreshStatus();
		} catch (e: any) {
			error = e.message;
		} finally {
			adding = false;
		}
	}

	function requestRemove(name: string) {
		confirmingRemove = confirmingRemove === name ? '' : name;
	}

	async function handleRemove(name: string) {
		confirmingRemove = '';
		try {
			await removeServer(name);
			await load();
			await store.refreshStatus();
		} catch (e: any) {
			error = e.message;
		}
	}
</script>

<h2 class="text-xl md:text-2xl font-bold mb-4 md:mb-6">{t('server.title')}</h2>

<form onsubmit={handleAdd} class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 mb-4 md:mb-6">
	<label for="invite-input" class="text-xs text-[var(--text-secondary)] mb-2 block uppercase tracking-wider font-medium">{t('server.add_label')}</label>
	<div class="flex flex-col sm:flex-row gap-3">
		<input
			id="invite-input"
			bind:value={inviteLink}
			placeholder={t('server.add_placeholder')}
			class="flex-1 px-3 py-2.5 bg-[var(--bg-primary)] border border-[var(--border)] rounded-lg text-[var(--text-primary)] outline-none transition-all font-mono text-sm"
			required
		/>
		<button
			type="submit"
			disabled={adding}
			class="px-5 py-2.5 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 text-white rounded-lg font-medium transition-all disabled:opacity-50 cursor-pointer active:scale-95 shadow-lg shadow-indigo-500/20 shrink-0"
		>
			{#if adding}
				<span class="flex items-center justify-center gap-2">
					<span class="spinner"></span>
					{t('server.adding')}
				</span>
			{:else}
				<span class="flex items-center gap-2">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
						<path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4" />
					</svg>
					{t('server.add_btn')}
				</span>
			{/if}
		</button>
	</div>
</form>

{#if success}
	<div class="bg-green-500/10 border border-green-500/20 text-green-400 px-4 py-2.5 rounded-xl text-sm mb-4 flex items-center gap-2 animate-in">
		<svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
			<path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
		</svg>
		{success}
	</div>
{/if}

{#if error}
	<div class="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-2.5 rounded-xl text-sm mb-4 flex items-center gap-2 animate-in">
		<svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
			<path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
		</svg>
		{error}
	</div>
{/if}

{#if loading}
	<div class="space-y-3">
		{#each [1,2] as _}
			<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4">
				<div class="skeleton h-5 w-32 mb-2"></div>
				<div class="skeleton h-4 w-48"></div>
			</div>
		{/each}
	</div>
{:else}
	<div class="space-y-3">
		{#each servers as server, i}
			<div class="card-interactive bg-[var(--bg-card)] rounded-xl p-4 animate-in" style="animation-delay: {i * 50}ms; animation-fill-mode: both">
				<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
					<div class="min-w-0">
						<div class="font-medium flex items-center gap-2">
							<svg class="w-4 h-4 text-[var(--accent)] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
								<path stroke-linecap="round" stroke-linejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
							</svg>
							{server.name}
						</div>
						<div class="text-sm text-[var(--text-secondary)] font-mono mt-1 truncate">
							{server.address}:{server.port}
							{#if server.sni}
								<span class="ml-2 text-xs opacity-70">{server.sni}</span>
							{/if}
						</div>
					</div>
					<div class="flex items-center gap-2 shrink-0">
						{#if latencies[server.name] !== undefined}
							{@const ms = latencies[server.name]}
							<span class="text-xs px-2 py-0.5 rounded-full font-mono {ms === -1 ? 'text-red-400 bg-red-500/10 border border-red-500/20' : ms < 100 ? 'text-green-400 bg-green-500/10 border border-green-500/20' : ms < 300 ? 'text-yellow-400 bg-yellow-500/10 border border-yellow-500/20' : 'text-orange-400 bg-orange-500/10 border border-orange-500/20'}">
								{ms === -1 ? '---' : `${ms}ms`}
							</span>
						{/if}
						{#if server.connected}
							<span class="text-xs px-2.5 py-1 rounded-full bg-[var(--success-glow)] text-green-400 border border-green-500/20">{t('status.connected')}</span>
						{/if}
						{#if confirmingRemove === server.name}
							<button
								onclick={() => handleRemove(server.name)}
								class="text-xs px-3 py-1.5 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30 border border-red-500/30 transition-all cursor-pointer active:scale-95 animate-in"
							>
								{t('server.remove_confirm', { name: server.name })}
							</button>
							<button
								onclick={() => confirmingRemove = ''}
								class="text-xs px-2 py-1.5 rounded-lg bg-[var(--bg-card-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all cursor-pointer"
							>
								&times;
							</button>
						{:else}
							<button
								onclick={() => requestRemove(server.name)}
								class="text-xs px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 transition-all cursor-pointer active:scale-95"
							>
								{t('server.remove')}
							</button>
						{/if}
					</div>
				</div>
			</div>
		{/each}

		{#if servers.length === 0}
			<div class="text-center py-16">
				<svg class="w-14 h-14 mx-auto mb-4 text-[var(--text-secondary)] opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1">
					<path stroke-linecap="round" stroke-linejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
				</svg>
				<p class="text-[var(--text-secondary)] mb-1">{t('server.none')}</p>
				<p class="text-xs text-[var(--text-secondary)] opacity-70">{t('server.none_hint')}</p>
			</div>
		{/if}
	</div>
{/if}
