<script lang="ts">
	import { getClients, revokeClient, formatBytes, formatDate } from '$lib/api';
	import { onMount } from 'svelte';

	let clients = $state<any[]>([]);
	let error = $state('');

	onMount(load);

	async function load() {
		try {
			clients = await getClients();
			error = '';
		} catch (e: any) {
			error = e.message || 'Failed to load clients';
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

<h2 class="text-2xl font-bold mb-6">Clients</h2>

{#if error}
	<div class="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded mb-4 text-sm">{error}</div>
{/if}

<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
	<table class="w-full">
		<thead>
			<tr class="border-b border-[var(--border)]">
				<th class="text-left p-3 text-sm text-[var(--text-secondary)] font-medium">Name</th>
				<th class="text-left p-3 text-sm text-[var(--text-secondary)] font-medium">Status</th>
				<th class="text-left p-3 text-sm text-[var(--text-secondary)] font-medium">Last Seen</th>
				<th class="text-left p-3 text-sm text-[var(--text-secondary)] font-medium">Protocol</th>
				<th class="text-right p-3 text-sm text-[var(--text-secondary)] font-medium">Traffic</th>
				<th class="text-right p-3 text-sm text-[var(--text-secondary)] font-medium">Actions</th>
			</tr>
		</thead>
		<tbody>
			{#each clients as client}
				<tr class="border-b border-[var(--border)] last:border-0 hover:bg-[var(--bg-primary)] transition-colors">
					<td class="p-3 font-medium">{client.name}</td>
					<td class="p-3">
						{#if client.revoked}
							<span class="text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-400">Revoked</span>
						{:else}
							<span class="text-xs px-2 py-0.5 rounded bg-green-500/20 text-green-400">Active</span>
						{/if}
					</td>
					<td class="p-3 text-[var(--text-secondary)] text-sm">{formatDate(client.last_connected_at)}</td>
					<td class="p-3 text-[var(--text-secondary)] text-sm">{client.last_protocol || '-'}</td>
					<td class="p-3 text-right text-sm">
						<span class="text-green-400">{formatBytes(client.bytes_up)}</span>
						/
						<span class="text-blue-400">{formatBytes(client.bytes_down)}</span>
					</td>
					<td class="p-3 text-right">
						{#if !client.revoked}
							<button
								onclick={() => handleRevoke(client.id, client.name)}
								class="text-xs px-2 py-1 rounded bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors cursor-pointer"
							>
								Revoke
							</button>
						{/if}
					</td>
				</tr>
			{/each}
			{#if clients.length === 0}
				<tr><td colspan="6" class="p-8 text-center text-[var(--text-secondary)]">No clients yet</td></tr>
			{/if}
		</tbody>
	</table>
</div>
