<script lang="ts">
	import { getConfig } from '$lib/api';
	import { onMount } from 'svelte';

	let config = $state<any>(null);
	let error = $state('');

	onMount(async () => {
		try {
			config = await getConfig();
		} catch (e: any) {
			error = e.message || 'Failed to load config';
		}
	});
</script>

<h2 class="text-2xl font-bold mb-6">Settings</h2>

{#if error}
	<div class="text-red-400">{error}</div>
{:else if config}
	<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-4">
		<div>
			<div class="text-sm text-[var(--text-secondary)]">Server Address</div>
			<div class="font-mono mt-1">{config.server_addr}</div>
		</div>
		<div>
			<div class="text-sm text-[var(--text-secondary)]">VLESS+Reality Port</div>
			<div class="font-mono mt-1">{config.listen_port}</div>
		</div>
		<div>
			<div class="text-sm text-[var(--text-secondary)]">Camouflage Domain</div>
			<div class="font-mono mt-1">{config.camouflage}</div>
		</div>
		<div>
			<div class="text-sm text-[var(--text-secondary)]">Reality Public Key</div>
			<div class="font-mono mt-1 text-sm break-all">{config.public_key}</div>
		</div>
		<div>
			<div class="text-sm text-[var(--text-secondary)]">Short ID</div>
			<div class="font-mono mt-1">{config.short_id}</div>
		</div>
	</div>
{:else}
	<div class="text-[var(--text-secondary)]">Loading...</div>
{/if}
