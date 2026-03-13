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

<h2 class="text-xl md:text-2xl font-bold mb-4 md:mb-6">Settings</h2>

{#if error}
	<div class="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-lg text-sm flex items-center gap-2 animate-in">
		<svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
			<path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
		</svg>
		{error}
	</div>
{:else if config}
	<div class="space-y-4">
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-6 animate-in">
			<h3 class="text-sm font-medium text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-2">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
				</svg>
				Server Configuration
			</h3>
			<div class="space-y-4">
				<div class="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4">
					<span class="text-sm text-[var(--text-secondary)] sm:w-40 shrink-0">Server Address</span>
					<span class="font-mono text-sm bg-[var(--bg-primary)] px-3 py-1.5 rounded-lg border border-[var(--border)] break-all">{config.server_addr}</span>
				</div>
				<div class="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4">
					<span class="text-sm text-[var(--text-secondary)] sm:w-40 shrink-0">VLESS+Reality Port</span>
					<span class="font-mono text-sm bg-[var(--bg-primary)] px-3 py-1.5 rounded-lg border border-[var(--border)]">{config.listen_port}</span>
				</div>
				<div class="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4">
					<span class="text-sm text-[var(--text-secondary)] sm:w-40 shrink-0">Camouflage Domain</span>
					<span class="font-mono text-sm bg-[var(--bg-primary)] px-3 py-1.5 rounded-lg border border-[var(--border)]">{config.camouflage}</span>
				</div>
				<div class="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4">
					<span class="text-sm text-[var(--text-secondary)] sm:w-40 shrink-0">Reality Public Key</span>
					<span class="font-mono text-xs bg-[var(--bg-primary)] px-3 py-1.5 rounded-lg border border-[var(--border)] break-all">{config.public_key}</span>
				</div>
				<div class="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4">
					<span class="text-sm text-[var(--text-secondary)] sm:w-40 shrink-0">Short ID</span>
					<span class="font-mono text-sm bg-[var(--bg-primary)] px-3 py-1.5 rounded-lg border border-[var(--border)]">{config.short_id}</span>
				</div>
			</div>
		</div>

		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-6 animate-in" style="animation-delay: 0.1s; animation-fill-mode: both">
			<h3 class="text-sm font-medium text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-2">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
				</svg>
				Security
			</h3>
			<div class="text-sm text-[var(--text-secondary)] space-y-2">
				<p>This server uses <span class="text-[var(--accent)] font-medium">VLESS + Reality</span> protocol with uTLS fingerprinting to appear as regular HTTPS traffic.</p>
				<p>DPI systems see what looks like a TLS 1.3 connection to <span class="font-mono text-xs">{config.camouflage}</span>.</p>
			</div>
		</div>
	</div>
{:else}
	<div class="space-y-4">
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-6">
			<div class="skeleton h-4 w-32 mb-4"></div>
			<div class="space-y-3">
				{#each [1,2,3,4,5] as _}
					<div class="flex gap-4">
						<div class="skeleton h-4 w-28"></div>
						<div class="skeleton h-4 w-40"></div>
					</div>
				{/each}
			</div>
		</div>
	</div>
{/if}
