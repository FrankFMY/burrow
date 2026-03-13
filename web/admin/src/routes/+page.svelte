<script lang="ts">
	import { getStats, formatBytes } from '$lib/api';
	import { onMount } from 'svelte';

	let stats = $state<any>(null);
	let error = $state('');

	onMount(async () => {
		try {
			stats = await getStats();
		} catch {
			error = 'Failed to load stats';
		}
	});
</script>

<h2 class="text-2xl font-bold mb-6">Dashboard</h2>

{#if error}
	<div class="text-red-400">{error}</div>
{:else if stats}
	<div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
			<div class="text-[var(--text-secondary)] text-sm mb-1">Active Clients</div>
			<div class="text-3xl font-bold text-[var(--success)]">{stats.active_clients}</div>
		</div>
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
			<div class="text-[var(--text-secondary)] text-sm mb-1">Total Traffic Up</div>
			<div class="text-3xl font-bold">{formatBytes(stats.total_bytes_up)}</div>
		</div>
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
			<div class="text-[var(--text-secondary)] text-sm mb-1">Total Traffic Down</div>
			<div class="text-3xl font-bold">{formatBytes(stats.total_bytes_down)}</div>
		</div>
	</div>

	<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
			<div class="text-[var(--text-secondary)] text-sm mb-1">Total Clients</div>
			<div class="text-2xl font-bold">{stats.total_clients}</div>
		</div>
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
			<div class="text-[var(--text-secondary)] text-sm mb-1">Revoked</div>
			<div class="text-2xl font-bold text-[var(--danger)]">{stats.revoked_clients}</div>
		</div>
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
			<div class="text-[var(--text-secondary)] text-sm mb-1">Total Connections</div>
			<div class="text-2xl font-bold">{stats.total_connections}</div>
		</div>
	</div>
{:else}
	<div class="text-[var(--text-secondary)]">Loading...</div>
{/if}
