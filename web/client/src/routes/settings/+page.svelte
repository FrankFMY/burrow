<script lang="ts">
	import { onMount } from 'svelte';

	let version = $state('');
	let configDir = $state('');
	let proxyAddr = $state('127.0.0.1:1080');

	onMount(async () => {
		try {
			const res = await fetch('http://127.0.0.1:9090/api/version');
			const data = await res.json();
			version = data.version || 'unknown';
			configDir = data.config_dir || '';
		} catch {
			version = 'daemon not running';
		}
	});
</script>

<h2 class="text-2xl font-bold mb-6">Settings</h2>

<div class="space-y-4">
	<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-4">
		<div>
			<div class="text-sm text-[var(--text-secondary)]">Version</div>
			<div class="font-mono mt-1">{version}</div>
		</div>
		<div>
			<div class="text-sm text-[var(--text-secondary)]">Local Proxy</div>
			<div class="font-mono mt-1">{proxyAddr}</div>
		</div>
		{#if configDir}
			<div>
				<div class="text-sm text-[var(--text-secondary)]">Config Directory</div>
				<div class="font-mono mt-1 text-sm break-all">{configDir}</div>
			</div>
		{/if}
	</div>

	<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
		<h3 class="font-medium mb-3">Proxy Configuration</h3>
		<div class="text-sm text-[var(--text-secondary)] space-y-2">
			<p>Configure your browser or system to use the following proxy:</p>
			<div class="bg-[var(--bg-primary)] rounded p-3 font-mono text-sm">
				<div>SOCKS5: <span class="text-[var(--accent)]">127.0.0.1:1080</span></div>
				<div>HTTP: <span class="text-[var(--accent)]">127.0.0.1:1080</span></div>
			</div>
			<p>Or set environment variables:</p>
			<div class="bg-[var(--bg-primary)] rounded p-3 font-mono text-xs">
				<div>export http_proxy=http://127.0.0.1:1080</div>
				<div>export https_proxy=http://127.0.0.1:1080</div>
				<div>export ALL_PROXY=socks5://127.0.0.1:1080</div>
			</div>
		</div>
	</div>
</div>
