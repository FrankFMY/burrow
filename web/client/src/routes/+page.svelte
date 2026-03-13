<script lang="ts">
	import { getStatus, connect, disconnect, getServers, formatBytes, formatDuration, type TunnelStatus, type Server } from '$lib/api';
	import { onMount, onDestroy } from 'svelte';

	let status = $state<TunnelStatus | null>(null);
	let servers = $state<Server[]>([]);
	let selectedServer = $state('');
	let killSwitch = $state(false);
	let loading = $state(false);
	let error = $state('');
	let pollInterval: ReturnType<typeof setInterval>;

	onMount(async () => {
		await refresh();
		pollInterval = setInterval(refresh, 2000);
	});

	onDestroy(() => {
		if (pollInterval) clearInterval(pollInterval);
	});

	async function refresh() {
		try {
			const [s, srv] = await Promise.all([
				getStatus().catch(() => null),
				getServers().catch(() => [])
			]);
			status = s;
			servers = srv;
			error = '';
		} catch {
			error = 'Cannot reach local daemon';
		}
	}

	async function handleToggle() {
		loading = true;
		error = '';
		try {
			if (status?.running) {
				await disconnect();
			} else {
				await connect(selectedServer || undefined, killSwitch);
			}
			await refresh();
		} catch (e: any) {
			error = e.message;
		} finally {
			loading = false;
		}
	}

	const connected = $derived(status?.running ?? false);
</script>

<div class="flex flex-col items-center gap-8 pt-12">
	<div class="text-center">
		<div class="text-sm text-[var(--text-secondary)] mb-2">
			{connected ? 'Connected' : 'Disconnected'}
		</div>
		<div
			class="w-36 h-36 rounded-full border-4 flex items-center justify-center cursor-pointer transition-all duration-300 select-none {connected ? 'border-[var(--success)] bg-[color-mix(in_srgb,var(--success)_10%,transparent)]' : 'border-[var(--border)] bg-[var(--bg-card)] hover:border-[var(--accent)]'} {loading ? 'opacity-50' : ''}"
			role="button"
			tabindex="0"
			onclick={handleToggle}
			onkeydown={(e) => e.key === 'Enter' && handleToggle()}
		>
			<svg class="w-12 h-12 {connected ? 'text-[var(--success)]' : 'text-[var(--text-secondary)]'}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
			</svg>
		</div>
	</div>

	{#if error}
		<div class="w-full bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-2 rounded text-sm text-center">
			{error}
		</div>
	{/if}

	{#if connected && status}
		<div class="grid grid-cols-3 gap-4 w-full">
			<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 text-center">
				<div class="text-xs text-[var(--text-secondary)] mb-1">Uptime</div>
				<div class="font-mono text-lg">{formatDuration(status.uptime)}</div>
			</div>
			<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 text-center">
				<div class="text-xs text-[var(--text-secondary)] mb-1">Upload</div>
				<div class="font-mono text-lg text-green-400">{formatBytes(status.bytes_up)}</div>
			</div>
			<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 text-center">
				<div class="text-xs text-[var(--text-secondary)] mb-1">Download</div>
				<div class="font-mono text-lg text-blue-400">{formatBytes(status.bytes_down)}</div>
			</div>
		</div>

		<div class="w-full bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
			<div class="flex justify-between text-sm">
				<span class="text-[var(--text-secondary)]">Server</span>
				<span class="font-mono">{status.server}</span>
			</div>
			<div class="flex justify-between text-sm mt-2">
				<span class="text-[var(--text-secondary)]">Protocol</span>
				<span class="font-mono">{status.protocol}</span>
			</div>
			<div class="flex justify-between text-sm mt-2">
				<span class="text-[var(--text-secondary)]">Kill Switch</span>
				<span class={status.kill_switch ? 'text-[var(--success)]' : 'text-[var(--text-secondary)]'}>
					{status.kill_switch ? 'Enabled' : 'Disabled'}
				</span>
			</div>
		</div>
	{:else}
		<div class="w-full space-y-4">
			{#if servers.length > 0}
				<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
					<div class="text-sm text-[var(--text-secondary)] mb-2">Server</div>
					<select
						bind:value={selectedServer}
						class="w-full px-3 py-2 bg-[var(--bg-primary)] border border-[var(--border)] rounded text-[var(--text-primary)] outline-none"
					>
						<option value="">Last used</option>
						{#each servers as server}
							<option value={server.name}>{server.name} ({server.address}:{server.port})</option>
						{/each}
					</select>
				</div>
			{/if}

			<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 flex items-center justify-between">
				<div>
					<div class="text-sm font-medium">Kill Switch</div>
					<div class="text-xs text-[var(--text-secondary)]">Block traffic if tunnel drops</div>
				</div>
				<button
					onclick={() => killSwitch = !killSwitch}
					class="w-12 h-7 rounded-full transition-colors cursor-pointer relative"
					class:bg-[var(--accent)]={killSwitch}
					class:bg-[var(--border)]={!killSwitch}
				>
					<div
						class="w-5 h-5 bg-white rounded-full absolute top-1 transition-transform"
						class:translate-x-6={killSwitch}
						class:translate-x-1={!killSwitch}
					></div>
				</button>
			</div>
		</div>
	{/if}
</div>
