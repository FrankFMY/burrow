<script lang="ts">
	import '../app.css';
	import { isAuthenticated, clearToken } from '$lib/api';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let { children } = $props();

	const isLogin = $derived(page.url.pathname.endsWith('/login'));
	const authed = $derived(isAuthenticated());

	onMount(() => {
		if (!authed && !isLogin) {
			goto('/admin/login');
		}
	});

	function logout() {
		clearToken();
		window.location.href = '/admin/login';
	}
</script>

<svelte:head>
	<title>Burrow Admin</title>
</svelte:head>

{#if isLogin}
	{@render children()}
{:else if authed}
	<div class="min-h-screen flex">
		<nav class="w-56 bg-[var(--bg-secondary)] border-r border-[var(--border)] p-4 flex flex-col">
			<h1 class="text-lg font-bold mb-6 text-[var(--accent)]">Burrow</h1>
			<a href="/admin" class="block py-2 px-3 rounded mb-1 hover:bg-[var(--bg-primary)] transition-colors"
				class:bg-[var(--bg-primary)]={page.url.pathname === '/admin'}>Dashboard</a>
			<a href="/admin/clients" class="block py-2 px-3 rounded mb-1 hover:bg-[var(--bg-primary)] transition-colors"
				class:bg-[var(--bg-primary)]={page.url.pathname.includes('/clients')}>Clients</a>
			<a href="/admin/invites" class="block py-2 px-3 rounded mb-1 hover:bg-[var(--bg-primary)] transition-colors"
				class:bg-[var(--bg-primary)]={page.url.pathname.includes('/invites')}>Invites</a>
			<a href="/admin/settings" class="block py-2 px-3 rounded mb-1 hover:bg-[var(--bg-primary)] transition-colors"
				class:bg-[var(--bg-primary)]={page.url.pathname.includes('/settings')}>Settings</a>
			<div class="mt-auto">
				<button onclick={logout} class="text-sm text-[var(--text-secondary)] hover:text-[var(--danger)] transition-colors cursor-pointer">
					Logout
				</button>
			</div>
		</nav>
		<main class="flex-1 p-8 overflow-auto">
			{@render children()}
		</main>
	</div>
{:else}
	<div class="min-h-screen flex items-center justify-center">
		<div class="text-[var(--text-secondary)]">Redirecting...</div>
	</div>
{/if}
