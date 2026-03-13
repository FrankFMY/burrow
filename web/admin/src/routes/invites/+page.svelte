<script lang="ts">
	import { getInvites, createInvite, revokeInvite, formatDate } from '$lib/api';
	import { onMount } from 'svelte';

	let clients = $state<any[]>([]);
	let newName = $state('');
	let newExpiry = $state('');
	let createdInvite = $state('');
	let creating = $state(false);
	let error = $state('');
	let copied = $state(false);
	let loading = $state(true);

	onMount(load);

	async function load() {
		try {
			clients = await getInvites();
			error = '';
		} catch (e: any) {
			error = e.message || 'Failed to load invites';
		} finally {
			loading = false;
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
		copied = true;
		setTimeout(() => copied = false, 2000);
	}
</script>

<h2 class="text-xl md:text-2xl font-bold mb-4 md:mb-6">Invites</h2>

{#if error}
	<div class="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-lg mb-4 text-sm flex items-center gap-2 animate-in">
		<svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
			<path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
		</svg>
		{error}
	</div>
{/if}

<form onsubmit={handleCreate} class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-5 mb-6">
	<div class="flex flex-col sm:flex-row gap-3 items-end">
		<div class="flex-1 w-full">
			<label for="invite-name" class="block text-xs text-[var(--text-secondary)] mb-1.5 uppercase tracking-wider font-medium">Name</label>
			<input
				id="invite-name"
				bind:value={newName}
				placeholder="e.g. Mom's phone"
				class="w-full px-3 py-2.5 bg-[var(--bg-primary)] border border-[var(--border)] rounded-lg text-[var(--text-primary)] outline-none transition-all"
				required
			/>
		</div>
		<div class="w-full sm:w-44">
			<label for="invite-expiry" class="block text-xs text-[var(--text-secondary)] mb-1.5 uppercase tracking-wider font-medium">Expires in</label>
			<select id="invite-expiry" bind:value={newExpiry} class="w-full px-3 py-2.5 bg-[var(--bg-primary)] border border-[var(--border)] rounded-lg text-[var(--text-primary)] outline-none transition-all cursor-pointer">
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
			class="w-full sm:w-auto px-5 py-2.5 bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 text-white rounded-lg font-medium transition-all disabled:opacity-50 cursor-pointer active:scale-95 shadow-lg shadow-blue-500/20"
		>
			{#if creating}
				<span class="flex items-center justify-center gap-2">
					<span class="spinner"></span>
					Creating...
				</span>
			{:else}
				<span class="flex items-center gap-2">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
						<path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4" />
					</svg>
					Create
				</span>
			{/if}
		</button>
	</div>
</form>

{#if createdInvite}
	<div class="bg-[var(--bg-card)] border border-[var(--accent)] rounded-xl p-4 md:p-5 mb-6 animate-in-scale shadow-lg shadow-blue-500/10">
		<div class="flex justify-between items-center mb-3">
			<span class="text-sm font-medium text-[var(--accent)] flex items-center gap-2">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
				</svg>
				Invite Link Created
			</span>
			<button onclick={copyInvite} class="text-xs px-3 py-1.5 rounded-lg bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] transition-all cursor-pointer active:scale-95 flex items-center gap-1.5">
				{#if copied}
					<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
						<path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
					</svg>
					Copied!
				{:else}
					<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
						<path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
					</svg>
					Copy
				{/if}
			</button>
		</div>
		<code class="text-xs text-[var(--text-secondary)] break-all block bg-[var(--bg-primary)] rounded-lg p-3 font-mono">{createdInvite}</code>
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
					<th class="text-left p-3 text-xs text-[var(--text-secondary)] font-medium uppercase tracking-wider">Created</th>
					<th class="text-left p-3 text-xs text-[var(--text-secondary)] font-medium uppercase tracking-wider">Expires</th>
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
						<td class="p-3 text-[var(--text-secondary)] text-sm">{formatDate(client.created_at)}</td>
						<td class="p-3 text-[var(--text-secondary)] text-sm">{client.expires_at ? formatDate(client.expires_at) : 'Never'}</td>
						<td class="p-3 text-right">
							{#if !client.revoked}
								<button onclick={() => handleRevoke(client.id, client.name)} class="text-xs px-3 py-1 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 transition-all cursor-pointer active:scale-95">Revoke</button>
							{/if}
						</td>
					</tr>
				{/each}
				{#if clients.length === 0}
					<tr>
						<td colspan="5" class="p-12 text-center">
							<svg class="w-12 h-12 mx-auto mb-3 text-[var(--text-secondary)] opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1">
								<path stroke-linecap="round" stroke-linejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
							</svg>
							<p class="text-[var(--text-secondary)]">No invites yet</p>
							<p class="text-xs text-[var(--text-secondary)] mt-1 opacity-70">Create one above to get started</p>
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
				<div class="flex items-center justify-between mb-2">
					<span class="font-medium">{client.name}</span>
					{#if client.revoked}
						<span class="badge-danger text-xs px-2 py-0.5 rounded-full">Revoked</span>
					{:else}
						<span class="badge-success text-xs px-2 py-0.5 rounded-full">Active</span>
					{/if}
				</div>
				<div class="text-sm text-[var(--text-secondary)] space-y-1">
					<div class="flex items-center gap-1.5">
						<svg class="w-3.5 h-3.5 opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
							<path stroke-linecap="round" stroke-linejoin="round" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
						</svg>
						Created: {formatDate(client.created_at)}
					</div>
					<div class="flex items-center gap-1.5">
						<svg class="w-3.5 h-3.5 opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
							<path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
						</svg>
						Expires: {client.expires_at ? formatDate(client.expires_at) : 'Never'}
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
					<path stroke-linecap="round" stroke-linejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
				</svg>
				<p class="text-[var(--text-secondary)]">No invites yet</p>
			</div>
		{/if}
	</div>
{/if}
