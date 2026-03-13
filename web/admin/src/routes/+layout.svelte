<script lang="ts">
	import '../app.css';
	import { isAuthenticated, clearAuth } from '$lib/api';
	import { getActiveServer } from '$lib/servers';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let { children } = $props();
	let menuOpen = $state(false);
	let authed = $state(false);
	let activeServerName = $state<string | null>(null);

	const isLogin = $derived(page.url.pathname.endsWith('/login'));

	onMount(() => {
		authed = isAuthenticated();
		if (!authed && !isLogin) {
			goto('/admin/login');
		}
		const active = getActiveServer();
		activeServerName = active?.name ?? null;
	});

	function logout() {
		clearAuth();
		authed = false;
		goto('/admin/login');
	}

	function navClick() {
		menuOpen = false;
		const active = getActiveServer();
		activeServerName = active?.name ?? null;
	}

	const links = [
		{ href: '/admin', label: 'Dashboard', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6', match: (p: string) => p === '/admin' || p === '/admin/' },
		{ href: '/admin/clients', label: 'Clients', icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z', match: (p: string) => p.includes('/clients') },
		{ href: '/admin/invites', label: 'Invites', icon: 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z', match: (p: string) => p.includes('/invites') },
		{ href: '/admin/settings', label: 'Settings', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z', match: (p: string) => p.includes('/settings') },
		{ href: '/admin/servers', label: 'Servers', icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-7-4h.01M17 16h.01', match: (p: string) => p.includes('/servers') },
	];
</script>

<svelte:head>
	<title>Burrow Admin</title>
</svelte:head>

{#if isLogin}
	{@render children()}
{:else if authed}
	<div class="min-h-screen flex flex-col md:flex-row">
		<!-- Mobile header -->
		<div class="md:hidden flex items-center justify-between bg-[var(--bg-secondary)] border-b border-[var(--border)] px-4 py-3">
			<div class="flex items-center gap-2.5">
				<div class="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center text-white font-bold text-sm shadow-lg shadow-blue-500/20">B</div>
				<div class="flex flex-col">
					<span class="font-semibold text-lg leading-tight">Burrow</span>
					{#if activeServerName}
						<span class="text-[10px] text-[var(--text-secondary)] leading-tight truncate max-w-[120px]">{activeServerName}</span>
					{/if}
				</div>
			</div>
			<button
				onclick={() => menuOpen = !menuOpen}
				class="p-2 rounded-lg hover:bg-[var(--bg-card)] transition-colors cursor-pointer"
				aria-label="Toggle menu"
			>
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					{#if menuOpen}
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
					{:else}
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
					{/if}
				</svg>
			</button>
		</div>

		<!-- Mobile nav overlay -->
		{#if menuOpen}
			<div class="md:hidden bg-[var(--bg-secondary)] border-b border-[var(--border)] px-4 pb-3 animate-slide-down">
				{#each links as link}
					<a
						href={link.href}
						onclick={navClick}
						class="flex items-center gap-3 py-2.5 px-3 rounded-lg mb-1 hover:bg-[var(--bg-card)] transition-all text-sm"
						class:nav-active={link.match(page.url.pathname)}
					>
						<svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
							<path stroke-linecap="round" stroke-linejoin="round" d={link.icon} />
						</svg>
						{link.label}
					</a>
				{/each}
				<button onclick={logout} class="w-full flex items-center gap-3 py-2.5 px-3 text-sm text-[var(--text-secondary)] hover:text-[var(--danger)] transition-colors cursor-pointer mt-2 border-t border-[var(--border)] pt-3">
					<svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
						<path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
					</svg>
					Logout
				</button>
			</div>
		{/if}

		<!-- Desktop sidebar -->
		<nav class="hidden md:flex w-60 bg-[var(--bg-secondary)] border-r border-[var(--border)] p-5 flex-col shrink-0">
			<div class="flex items-center gap-2.5 mb-8">
				<div class="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center text-white font-bold shadow-lg shadow-blue-500/20">B</div>
				<div class="flex flex-col min-w-0">
					<span class="font-bold text-lg leading-tight">Burrow</span>
					{#if activeServerName}
						<span class="text-[10px] text-[var(--text-secondary)] leading-tight truncate">{activeServerName}</span>
					{/if}
				</div>
			</div>
			<div class="space-y-1">
				{#each links as link}
					<a
						href={link.href}
						class="flex items-center gap-3 py-2.5 px-3 rounded-lg hover:bg-[var(--bg-card)] transition-all text-sm"
						class:nav-active={link.match(page.url.pathname)}
					>
						<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
							<path stroke-linecap="round" stroke-linejoin="round" d={link.icon} />
						</svg>
						{link.label}
					</a>
				{/each}
			</div>
			<div class="mt-auto pt-4 border-t border-[var(--border)]">
				<button onclick={logout} class="flex items-center gap-3 text-sm text-[var(--text-secondary)] hover:text-[var(--danger)] transition-colors cursor-pointer py-2 px-3 w-full rounded-lg hover:bg-[var(--danger-glow)]">
					<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
						<path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
					</svg>
					Logout
				</button>
			</div>
		</nav>

		<main class="flex-1 p-4 md:p-8 overflow-auto">
			<div class="animate-in">
				{@render children()}
			</div>
		</main>
	</div>
{:else}
	<div class="min-h-screen flex items-center justify-center">
		<div class="spinner text-[var(--accent)]" style="width:24px;height:24px;border-width:3px"></div>
	</div>
{/if}
