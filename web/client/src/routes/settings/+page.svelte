<script lang="ts">
	import { onMount } from 'svelte';

	let version = $state('');
	let configDir = $state('');
	let loading = $state(true);

	onMount(async () => {
		try {
			const res = await fetch('http://127.0.0.1:9090/api/version');
			const data = await res.json();
			version = data.version || 'unknown';
			configDir = data.config_dir || '';
		} catch {
			version = 'daemon not running';
		} finally {
			loading = false;
		}
	});
</script>

<h2 class="text-xl md:text-2xl font-bold mb-4 md:mb-6">Settings</h2>

{#if loading}
	<div class="space-y-4">
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-6">
			<div class="skeleton h-4 w-24 mb-4"></div>
			<div class="space-y-3">
				{#each [1,2,3] as _}
					<div class="skeleton h-5 w-48"></div>
				{/each}
			</div>
		</div>
	</div>
{:else}
	<div class="space-y-4">
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-6 animate-in">
			<h3 class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-2">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
					<path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
				</svg>
				About
			</h3>
			<div class="space-y-3">
				<div class="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4">
					<span class="text-sm text-[var(--text-secondary)] sm:w-32 shrink-0">Version</span>
					<span class="font-mono text-sm">{version}</span>
				</div>
				<div class="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4">
					<span class="text-sm text-[var(--text-secondary)] sm:w-32 shrink-0">Local Proxy</span>
					<span class="font-mono text-sm">127.0.0.1:1080</span>
				</div>
				{#if configDir}
					<div class="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4">
						<span class="text-sm text-[var(--text-secondary)] sm:w-32 shrink-0">Config Dir</span>
						<span class="font-mono text-xs break-all">{configDir}</span>
					</div>
				{/if}
			</div>
		</div>

		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-6 animate-in" style="animation-delay: 0.1s; animation-fill-mode: both">
			<h3 class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-2">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
					<path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
				</svg>
				Proxy Configuration
			</h3>
			<div class="text-sm text-[var(--text-secondary)] space-y-3">
				<p>Configure your browser or system to use the proxy below:</p>
				<div class="bg-[var(--bg-primary)] rounded-lg p-3 font-mono text-sm border border-[var(--border)] space-y-1">
					<div class="flex flex-col sm:flex-row sm:items-center gap-1">
						<span class="text-[var(--text-secondary)] sm:w-16">SOCKS5:</span>
						<span class="text-[var(--accent)]">127.0.0.1:1080</span>
					</div>
					<div class="flex flex-col sm:flex-row sm:items-center gap-1">
						<span class="text-[var(--text-secondary)] sm:w-16">HTTP:</span>
						<span class="text-[var(--accent)]">127.0.0.1:1080</span>
					</div>
				</div>
				<p>Or set environment variables:</p>
				<div class="bg-[var(--bg-primary)] rounded-lg p-3 font-mono text-xs border border-[var(--border)] space-y-0.5 overflow-x-auto">
					<div>export http_proxy=http://127.0.0.1:1080</div>
					<div>export https_proxy=http://127.0.0.1:1080</div>
					<div>export ALL_PROXY=socks5://127.0.0.1:1080</div>
				</div>
			</div>
		</div>
	</div>
{/if}
