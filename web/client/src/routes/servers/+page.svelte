<script lang="ts">
	import { getServers, addServer, removeServer, type Server } from '$lib/api';
	import { onMount } from 'svelte';

	let servers = $state<Server[]>([]);
	let inviteLink = $state('');
	let adding = $state(false);
	let error = $state('');

	onMount(load);

	async function load() {
		try {
			servers = await getServers();
		} catch {
			error = 'Cannot reach local daemon';
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

<h2 class="text-2xl font-bold mb-6">Servers</h2>

<form onsubmit={handleAdd} class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 mb-6">
	<div class="text-sm text-[var(--text-secondary)] mb-2">Add server from invite link</div>
	<div class="flex gap-3">
		<input
			bind:value={inviteLink}
			placeholder="burrow://connect/..."
			class="flex-1 px-3 py-2 bg-[var(--bg-primary)] border border-[var(--border)] rounded text-[var(--text-primary)] outline-none focus:border-[var(--accent)] font-mono text-sm"
			required
		/>
		<button
			type="submit"
			disabled={adding}
			class="px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded font-medium transition-colors disabled:opacity-50 cursor-pointer"
		>
			Add
		</button>
	</div>
</form>

{#if error}
	<div class="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-2 rounded text-sm mb-4">
		{error}
	</div>
{/if}

<div class="space-y-2">
	{#each servers as server}
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 flex items-center justify-between hover:bg-[var(--bg-card-hover)] transition-colors">
			<div>
				<div class="font-medium">{server.name}</div>
				<div class="text-sm text-[var(--text-secondary)] font-mono">
					{server.address}:{server.port}
					<span class="ml-2 text-xs">{server.sni}</span>
				</div>
			</div>
			<div class="flex items-center gap-3">
				{#if server.connected}
					<span class="text-xs px-2 py-0.5 rounded bg-green-500/20 text-green-400">Connected</span>
				{/if}
				<button
					onclick={() => handleRemove(server.name)}
					class="text-xs px-2 py-1 rounded bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors cursor-pointer"
				>
					Remove
				</button>
			</div>
		</div>
	{/each}

	{#if servers.length === 0}
		<div class="text-center py-12 text-[var(--text-secondary)]">
			No servers configured. Add one using an invite link above.
		</div>
	{/if}
</div>
