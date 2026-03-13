<script lang="ts">
	import { onMount } from 'svelte';
	import { store } from '$lib/stores.svelte';
	import { i18n, t } from '$lib/i18n.svelte';

	let version = $state('');
	let configDir = $state('');
	let loading = $state(true);

	onMount(async () => {
		await store.init();

		try {
			const verRes = await fetch('http://127.0.0.1:9090/api/version')
				.then((r) => r.json())
				.catch(() => ({}));
			version = verRes.version || 'unknown';
			configDir = verRes.config_dir || '';
		} catch {
			version = 'daemon not running';
		} finally {
			loading = false;
		}
	});

	async function toggleTunMode() {
		await store.updatePreference({ tun_mode: !store.preferences.tun_mode });
	}

	async function toggleKillSwitch() {
		await store.updatePreference({ kill_switch: !store.preferences.kill_switch });
	}

	async function toggleAutoConnect() {
		await store.updatePreference({ auto_connect: !store.preferences.auto_connect });
	}
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
		<!-- Preferences -->
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-6 animate-in">
			<h3 class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-2">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
					<path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
					<path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
				</svg>
				Preferences
			</h3>

			<div class="space-y-1">
				<button
					onclick={toggleTunMode}
					class="w-full flex items-center justify-between p-3 rounded-lg hover:bg-[var(--bg-card-hover)] transition-colors cursor-pointer"
				>
					<div class="text-left">
						<div class="text-sm font-medium flex items-center gap-2">
							<svg class="w-4 h-4 text-[var(--accent)]" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
								<path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
							</svg>
							VPN Mode
						</div>
						<div class="text-xs text-[var(--text-secondary)] mt-0.5">{store.preferences.tun_mode ? 'All traffic through VPN' : 'Manual proxy (SOCKS5/HTTP)'}</div>
					</div>
					<div
						class="w-12 h-7 rounded-full transition-all duration-200 relative shrink-0"
						class:bg-[var(--accent)]={store.preferences.tun_mode}
						class:shadow-[0_0_12px_var(--accent-glow)]={store.preferences.tun_mode}
						class:bg-[var(--border)]={!store.preferences.tun_mode}
					>
						<div class="w-5 h-5 bg-white rounded-full absolute top-1 transition-transform duration-200 shadow-sm" class:translate-x-6={store.preferences.tun_mode} class:translate-x-1={!store.preferences.tun_mode}></div>
					</div>
				</button>

				<button
					onclick={toggleKillSwitch}
					class="w-full flex items-center justify-between p-3 rounded-lg hover:bg-[var(--bg-card-hover)] transition-colors cursor-pointer"
				>
					<div class="text-left">
						<div class="text-sm font-medium flex items-center gap-2">
							<svg class="w-4 h-4 text-[var(--accent)]" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
								<path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
							</svg>
							Kill Switch
						</div>
						<div class="text-xs text-[var(--text-secondary)] mt-0.5">Block all traffic if VPN disconnects</div>
					</div>
					<div
						class="w-12 h-7 rounded-full transition-all duration-200 relative shrink-0"
						class:bg-[var(--accent)]={store.preferences.kill_switch}
						class:shadow-[0_0_12px_var(--accent-glow)]={store.preferences.kill_switch}
						class:bg-[var(--border)]={!store.preferences.kill_switch}
					>
						<div class="w-5 h-5 bg-white rounded-full absolute top-1 transition-transform duration-200 shadow-sm" class:translate-x-6={store.preferences.kill_switch} class:translate-x-1={!store.preferences.kill_switch}></div>
					</div>
				</button>

				<button
					onclick={toggleAutoConnect}
					class="w-full flex items-center justify-between p-3 rounded-lg hover:bg-[var(--bg-card-hover)] transition-colors cursor-pointer"
				>
					<div class="text-left">
						<div class="text-sm font-medium flex items-center gap-2">
							<svg class="w-4 h-4 text-[var(--accent)]" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
								<path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
							</svg>
							Auto-Connect
						</div>
						<div class="text-xs text-[var(--text-secondary)] mt-0.5">Connect automatically when app opens</div>
					</div>
					<div
						class="w-12 h-7 rounded-full transition-all duration-200 relative shrink-0"
						class:bg-[var(--accent)]={store.preferences.auto_connect}
						class:shadow-[0_0_12px_var(--accent-glow)]={store.preferences.auto_connect}
						class:bg-[var(--border)]={!store.preferences.auto_connect}
					>
						<div class="w-5 h-5 bg-white rounded-full absolute top-1 transition-transform duration-200 shadow-sm" class:translate-x-6={store.preferences.auto_connect} class:translate-x-1={!store.preferences.auto_connect}></div>
					</div>
				</button>
			</div>
		</div>

		<!-- Advanced: Proxy info (only relevant when TUN mode is off) -->
		{#if !store.preferences.tun_mode}
			<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-6 animate-in" style="animation-delay: 0.05s; animation-fill-mode: both">
				<h3 class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-2">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
						<path stroke-linecap="round" stroke-linejoin="round" d="M6.115 5.19l.319 1.913A6 6 0 008.11 10.36L9.75 12l-.387.775c-.217.433-.132.956.21 1.298l1.348 1.348c.21.21.329.497.329.795v1.089c0 .426.24.815.622 1.006l.153.076c.433.217.956.132 1.298-.21l.723-.723a8.7 8.7 0 002.288-4.042 1.087 1.087 0 00-.358-1.099l-1.33-1.108c-.251-.21-.582-.299-.905-.245l-1.17.195a1.125 1.125 0 01-.98-.314l-.295-.295a1.125 1.125 0 010-1.591l.13-.132a1.125 1.125 0 011.3-.21l.603.302a.809.809 0 001.086-1.086L14.25 7.5l1.256-.837a4.5 4.5 0 001.528-1.732l.146-.292M6.115 5.19A9 9 0 1017.18 4.64M6.115 5.19A8.965 8.965 0 0112 3c1.929 0 3.72.607 5.18 1.64" />
					</svg>
					Proxy Configuration
				</h3>
				<div class="text-sm text-[var(--text-secondary)] space-y-3">
					<p>When VPN Mode is off, configure apps to use these proxies:</p>
					<div class="bg-[var(--bg-primary)] rounded-lg p-3 font-mono text-sm border border-[var(--border)] space-y-1">
						<div class="flex items-center gap-2">
							<span class="text-[var(--text-secondary)] w-16">SOCKS5:</span>
							<span class="text-[var(--accent)]">127.0.0.1:1080</span>
						</div>
						<div class="flex items-center gap-2">
							<span class="text-[var(--text-secondary)] w-16">HTTP:</span>
							<span class="text-[var(--accent)]">127.0.0.1:1080</span>
						</div>
					</div>
				</div>
			</div>
		{/if}

		<!-- Language -->
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-6 animate-in" style="animation-delay: 0.08s; animation-fill-mode: both">
			<h3 class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-2">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
					<path stroke-linecap="round" stroke-linejoin="round" d="M10.5 21l5.25-11.25L21 21m-9-3h7.5M3 5.621a48.474 48.474 0 016-.371m0 0c1.12 0 2.233.038 3.334.114M9 5.25V3m3.334 2.364C11.176 10.658 7.69 15.08 3 17.502m9.334-12.138c.896.061 1.785.147 2.666.257m-4.589 8.495a18.023 18.023 0 01-3.827-5.802" />
				</svg>
				{t('settings.language')}
			</h3>
			<div class="flex gap-2">
				{#each i18n.locales as loc}
					<button
						onclick={() => i18n.locale = loc.code}
						class="px-4 py-2 rounded-lg text-sm font-medium transition-all cursor-pointer {i18n.locale === loc.code ? 'bg-[var(--accent)] text-white shadow-lg shadow-indigo-500/20' : 'bg-[var(--bg-primary)] border border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--accent)]/50'}"
					>
						{loc.label}
					</button>
				{/each}
			</div>
		</div>

		<!-- About -->
		<div class="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 md:p-6 animate-in" style="animation-delay: 0.1s; animation-fill-mode: both">
			<h3 class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-2">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
					<path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />
				</svg>
				{t('settings.about')}
			</h3>
			<div class="space-y-3">
				<div class="flex items-center justify-between">
					<span class="text-sm text-[var(--text-secondary)]">{t('settings.version')}</span>
					<span class="font-mono text-sm">{version}</span>
				</div>
				{#if configDir}
					<div class="flex items-center justify-between gap-4">
						<span class="text-sm text-[var(--text-secondary)] shrink-0">{t('settings.config')}</span>
						<span class="font-mono text-xs text-[var(--text-secondary)] truncate">{configDir}</span>
					</div>
				{/if}
			</div>
		</div>
	</div>
{/if}
