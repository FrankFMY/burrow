<script lang="ts">
	import { getClients, revokeClient, formatBytes, formatDate } from '$lib/api';
	import { onMount } from 'svelte';

	let clients = $state<any[]>([]);
	let error = $state('');
	let loading = $state(true);

	onMount(load);

	async function load() {
		try {
			clients = await getClients();
			error = '';
		} catch (e: any) {
			error = e.message || 'Failed to load clients';
		} finally {
			loading = false;
		}
	}

	async function handleRevoke(id: string, name: string) {
		if (!confirm(`Revoke access for "${name}"?`)) return;
		try {
			await revokeClient(id);
			await load();
		} catch (e: any) {
			error = e.message || 'Failed to revoke client';
		}
	}
</script>

<div class="flex items-center justify-between mb-4 md:mb-6">
	<h2 class="text-xl md:text-2xl font-bold">Clients</h2>
	<span class="text-sm text-[var(--text-secondary)]">{clients.length} total</span>
</div>

{#if error}
	<div class="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-lg mb-4 text-sm flex items-center gap-2 animate-in">
		<svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
			<path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
		</svg>
		{error}
	</div>
{/if}

{#if loading}
	<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl overflow-hidden">
		{#each [1,2,3] as _}
			<div class="p-4 border-b border-[var(--border)] last:border-0">
				<div class="flex items-center gap-4">
					<div class="skeleton w-32 h-5"></div>
					<div class="skeleton w-16 h-5"></div>
					<div class="flex-1"></div>
					<div class="skeleton w-20 h-5"></div>
				</div>
			</div>
		{/each}
	</div>
{:else}
	<!-- Desktop table -->
	<div class="hidden md:block bg-[var(--bg-card)] border border-[var(--border)] rounded-xl overflow-hidden">
		<table class="w-full">
			<thead>
				<tr class="border-b border-[var(--border)] bg-[var(--bg-secondary)]">
					<th class="text-left p-3 text-xs text-[var(--text-secondary)] font-medium uppercase tracking-wider">Name</th>
					<th class="text-left p-3 text-xs text-[var(--text-secondary)] font-medium uppercase tracking-wider">Status</th>
					<th class="text-left p-3 text-xs text-[var(--text-secondary)] font-medium uppercase tracking-wider">Last Seen</th>
					<th class="text-left p-3 text-xs text-[var(--text-secondary)] font-medium uppercase tracking-wider">Protocol</th>
					<th class="text-right p-3 text-xs text-[var(--text-secondary)] font-medium uppercase tracking-wider">Traffic</th>
					<th class="text-right p-3 text-xs text-[var(--text-secondary)] font-medium uppercase tracking-wider">Actions</th>
				</tr>
			</thead>
			<tbody>
				{#each clients as client, i}
					<tr class="border-b border-[var(--border)] last:border-0 row-hover animate-in" style="animation-delay: {i * 30}ms; animation-fill-mode: both">
						<td class="p-3 font-medium">{client.name}</td>
						<td class="p-3">
							{#if client.revoked}
								<span class="badge-danger text-xs px-2 py-0.5 rounded-full">Revoked</span>
							{:else}
								<span class="badge-success text-xs px-2 py-0.5 rounded-full">Active</span>
							{/if}
						</td>
						<td class="p-3 text-[var(--text-secondary)] text-sm">{formatDate(client.last_connected_at)}</td>
						<td class="p-3 text-[var(--text-secondary)] text-sm font-mono">{client.last_protocol || '-'}</td>
						<td class="p-3 text-right text-sm">
							<span class="text-green-400">{formatBytes(client.bytes_up)}</span>
							<span class="text-[var(--text-secondary)] mx-1">/</span>
							<span class="text-blue-400">{formatBytes(client.bytes_down)}</span>
						</td>
						<td class="p-3 text-right">
							{#if !client.revoked}
								<button onclick={() => handleRevoke(client.id, client.name)} class="text-xs px-3 py-1 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 transition-all cursor-pointer active:scale-95">Revoke</button>
							{/if}
						</td>
					</tr>
				{/each}
				{#if clients.length === 0}
					<tr>
						<td colspan="6" class="p-12 text-center">
							<svg class="w-12 h-12 mx-auto mb-3 text-[var(--text-secondary)] opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1">
								<path stroke-linecap="round" stroke-linejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
							</svg>
							<p class="text-[var(--text-secondary)]">No clients yet</p>
							<p class="text-xs text-[var(--text-secondary)] mt-1 opacity-70">Create an invite to add your first client</p>
						</td>
					</tr>
				{/if}
			</tbody>
		</table>
	</div>

	<!-- Mobile cards -->
	<div class="md:hidden space-y-3">
		{#each clients as client, i}
			<div class="card-interactive bg-[var(--bg-card)] rounded-xl p-4 animate-in" style="animation-delay: {i * 50}ms; animation-fill-mode: both">
				<div class="flex items-center justify-between mb-3">
					<span class="font-medium">{client.name}</span>
					{#if client.revoked}
						<span class="badge-danger text-xs px-2 py-0.5 rounded-full">Revoked</span>
					{:else}
						<span class="badge-success text-xs px-2 py-0.5 rounded-full">Active</span>
					{/if}
				</div>
				<div class="grid grid-cols-2 gap-2 text-sm text-[var(--text-secondary)]">
					<div class="flex items-center gap-1.5">
						<svg class="w-3.5 h-3.5 opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
							<path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
						</svg>
						{formatDate(client.last_connected_at)}
					</div>
					<div class="flex items-center gap-1.5">
						<svg class="w-3.5 h-3.5 opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
							<path stroke-linecap="round" stroke-linejoin="round" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2z" />
						</svg>
						{client.last_protocol || '-'}
					</div>
					<div>
						<span class="text-green-400">{formatBytes(client.bytes_up)}</span> up
					</div>
					<div>
						<span class="text-blue-400">{formatBytes(client.bytes_down)}</span> down
					</div>
				</div>
				{#if !client.revoked}
					<button onclick={() => handleRevoke(client.id, client.name)} class="mt-3 text-xs px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 transition-all cursor-pointer active:scale-95">Revoke</button>
				{/if}
			</div>
		{/each}
		{#if clients.length === 0}
			<div class="text-center py-16">
				<svg class="w-12 h-12 mx-auto mb-3 text-[var(--text-secondary)] opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1">
					<path stroke-linecap="round" stroke-linejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
				</svg>
				<p class="text-[var(--text-secondary)]">No clients yet</p>
			</div>
		{/if}
	</div>
{/if}
