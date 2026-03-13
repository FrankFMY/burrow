<script lang="ts">
	import { getInvites, createInvite, revokeInvite, formatDate } from '$lib/api';
	import { onMount } from 'svelte';

	let clients = $state<any[]>([]);
	let newName = $state('');
	let newExpiry = $state('');
	let createdInvite = $state('');
	let creating = $state(false);
	let error = $state('');

	onMount(load);

	async function load() {
		try {
			clients = await getInvites();
			error = '';
		} catch (e: any) {
			error = e.message || 'Failed to load invites';
		}
	}

	async function handleCreate(e: Event) {
		e.preventDefault();
		if (!newName.trim()) return;
		creating = true;
		error = '';
		try {
			const result = await createInvite(newName.trim(), newExpiry || undefined);
			createdInvite = result.invite;
			newName = '';
			newExpiry = '';
			await load();
		} catch (e: any) {
			error = e.message || 'Failed to create invite';
		} finally {
			creating = false;
		}
	}

	async function handleRevoke(id: string, name: string) {
		if (!confirm(`Revoke invite for "${name}"?`)) return;
		try {
			await revokeInvite(id);
			await load();
		} catch (e: any) {
			error = e.message || 'Failed to revoke invite';
		}
	}

	function copyInvite() {
		navigator.clipboard.writeText(createdInvite);
	}
</script>

<h2 class="text-2xl font-bold mb-6">Invites</h2>

{#if error}
	<div class="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded mb-4 text-sm">{error}</div>
{/if}

<form onsubmit={handleCreate} class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 mb-6 flex gap-3 items-end">
	<div class="flex-1">
		<label for="invite-name" class="block text-sm text-[var(--text-secondary)] mb-1">Name</label>
		<input
			id="invite-name"
			bind:value={newName}
			placeholder="e.g. Mom's phone"
			class="w-full px-3 py-2 bg-[var(--bg-primary)] border border-[var(--border)] rounded text-[var(--text-primary)] outline-none focus:border-[var(--accent)]"
			required
		/>
	</div>
	<div class="w-40">
		<label for="invite-expiry" class="block text-sm text-[var(--text-secondary)] mb-1">Expires in</label>
		<select id="invite-expiry" bind:value={newExpiry} class="w-full px-3 py-2 bg-[var(--bg-primary)] border border-[var(--border)] rounded text-[var(--text-primary)] outline-none">
			<option value="">Never</option>
			<option value="24h">24 hours</option>
			<option value="168h">7 days</option>
			<option value="720h">30 days</option>
			<option value="8760h">1 year</option>
		</select>
	</div>
	<button
		type="submit"
		disabled={creating}
		class="px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded font-medium transition-colors disabled:opacity-50 cursor-pointer"
	>
		Create
	</button>
</form>

{#if createdInvite}
	<div class="bg-[var(--bg-card)] border border-[var(--accent)] rounded-lg p-4 mb-6">
		<div class="flex justify-between items-center mb-2">
			<span class="text-sm font-medium text-[var(--accent)]">Invite Link Created</span>
			<button onclick={copyInvite} class="text-xs px-2 py-1 rounded bg-[var(--accent)]/20 text-[var(--accent)] hover:bg-[var(--accent)]/30 transition-colors cursor-pointer">
				Copy
			</button>
		</div>
		<code class="text-xs text-[var(--text-secondary)] break-all block">{createdInvite}</code>
	</div>
{/if}

<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
	<table class="w-full">
		<thead>
			<tr class="border-b border-[var(--border)]">
				<th class="text-left p-3 text-sm text-[var(--text-secondary)] font-medium">Name</th>
				<th class="text-left p-3 text-sm text-[var(--text-secondary)] font-medium">Status</th>
				<th class="text-left p-3 text-sm text-[var(--text-secondary)] font-medium">Created</th>
				<th class="text-left p-3 text-sm text-[var(--text-secondary)] font-medium">Expires</th>
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
					<td class="p-3 text-[var(--text-secondary)] text-sm">{formatDate(client.created_at)}</td>
					<td class="p-3 text-[var(--text-secondary)] text-sm">{client.expires_at ? formatDate(client.expires_at) : 'Never'}</td>
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
				<tr><td colspan="5" class="p-8 text-center text-[var(--text-secondary)]">No invites yet</td></tr>
			{/if}
		</tbody>
	</table>
</div>
