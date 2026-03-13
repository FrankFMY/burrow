<script lang="ts">
	import '../app.css';
	import { page } from '$app/state';

	let { children } = $props();
	let menuOpen = $state(false);

	const links = [
		{ href: '/', label: 'Connect', icon: 'M13 10V3L4 14h7v7l9-11h-7z', match: (p: string) => p === '/' },
		{ href: '/servers', label: 'Servers', icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2', match: (p: string) => p.startsWith('/servers') },
		{ href: '/settings', label: 'Settings', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z', match: (p: string) => p.startsWith('/settings') },
	];
</script>

<svelte:head>
	<link rel="preconnect" href="https://fonts.googleapis.com" />
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous" />
	<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
</svelte:head>

<div class="min-h-screen flex flex-col">
	<!-- Header -->
	<header class="border-b border-[var(--border)] px-4 md:px-6 py-3 md:py-4 flex items-center justify-between bg-[var(--bg-secondary)]/80 backdrop-blur-xl sticky top-0 z-50">
		<div class="flex items-center gap-2.5">
			<div class="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white font-bold text-sm shadow-lg shadow-indigo-500/20">B</div>
			<span class="font-semibold text-lg">Burrow</span>
		</div>

		<!-- Desktop nav -->
		<nav class="hidden sm:flex gap-1">
			{#each links as link}
				<a
					href={link.href}
					class="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-all hover:bg-[var(--bg-card)]"
					class:bg-[var(--accent-glow)]={link.match(page.url.pathname)}
					class:text-[var(--accent)]={link.match(page.url.pathname)}
				>
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
						<path stroke-linecap="round" stroke-linejoin="round" d={link.icon} />
					</svg>
					{link.label}
				</a>
			{/each}
		</nav>

		<!-- Mobile menu button -->
		<button
			onclick={() => menuOpen = !menuOpen}
			class="sm:hidden p-2 rounded-lg hover:bg-[var(--bg-card)] transition-colors cursor-pointer"
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
	</header>

	<!-- Mobile nav dropdown -->
	{#if menuOpen}
		<div class="sm:hidden bg-[var(--bg-secondary)] border-b border-[var(--border)] px-4 py-2 animate-in">
			{#each links as link}
				<a
					href={link.href}
					onclick={() => menuOpen = false}
					class="flex items-center gap-3 py-2.5 px-3 rounded-lg text-sm transition-all hover:bg-[var(--bg-card)]"
					class:bg-[var(--accent-glow)]={link.match(page.url.pathname)}
					class:text-[var(--accent)]={link.match(page.url.pathname)}
				>
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
						<path stroke-linecap="round" stroke-linejoin="round" d={link.icon} />
					</svg>
					{link.label}
				</a>
			{/each}
		</div>
	{/if}

	<main class="flex-1 p-4 md:p-6 max-w-2xl mx-auto w-full animate-in">
		{@render children()}
	</main>
</div>
