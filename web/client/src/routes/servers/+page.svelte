<script lang="ts">
	import { getServers, addServer, removeServer, type Server } from '$lib/api';
	import { onMount } from 'svelte';

	let servers = $state<Server[]>([]);
	let inviteLink = $state('');
	let adding = $state(false);
	let error = $state('');
	let loading = $state(true);

	onMount(load);

	async function load() {
		try {
			servers = await getServers();
		} catch {
			error = 'Cannot reach local daemon';
		} finally {
			loading = false;
		}
	}

	async function handleAdd(e: Event) {
		e.preventDefault();
		if (!inviteLink.trim()) return;
		adding = true;
		error = '';
		try {
			await addServer(inviteLink.trim());
			inviteLink = '';
			await load();
		} catch (e: any) {
			error = e.message;
		} finally {
			adding = false;
		}
	}

	async function handleRemove(name: string) {
		if (!confirm(`Remove server "${name}"?`)) return;
		try {
			await removeServer(name);
			await load();
		} catch (e: any) {
			error = e.message;
		}
	}
</script>

<h2 class="text-xl md:text-2xl font-bold mb-4 md:mb-6">Servers</h2>

<form onsubmit={handleAdd} class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 mb-4 md:mb-6">
	<label for="invite-input" class="text-xs text-[var(--text-secondary)] mb-2 block uppercase tracking-wider font-medium">Add server from invite link</label>
	<div class="flex flex-col sm:flex-row gap-3">
		<input
			id="invite-input"
			bind:value={inviteLink}
			placeholder="burrow://connect/..."
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
					Adding...
				</span>
			{:else}
				<span class="flex items-center gap-2">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
						<path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4" />
					</svg>
					Add
				</span>
			{/if}
		</button>
	</div>
</form>

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
						{#if server.connected}
							<span class="text-xs px-2.5 py-1 rounded-full bg-[var(--success-glow)] text-green-400 border border-green-500/20">Connected</span>
						{/if}
						<button
							onclick={() => handleRemove(server.name)}
							class="text-xs px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 transition-all cursor-pointer active:scale-95"
						>
							Remove
						</button>
					</div>
				</div>
			</div>
		{/each}

		{#if servers.length === 0}
			<div class="text-center py-16">
				<svg class="w-14 h-14 mx-auto mb-4 text-[var(--text-secondary)] opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1">
					<path stroke-linecap="round" stroke-linejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
				</svg>
				<p class="text-[var(--text-secondary)] mb-1">No servers configured</p>
				<p class="text-xs text-[var(--text-secondary)] opacity-70">Paste an invite link above to add your first server</p>
			</div>
		{/if}
	</div>
{/if}
