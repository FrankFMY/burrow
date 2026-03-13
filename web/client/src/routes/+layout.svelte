<script lang="ts">
	import '../app.css';

	let { children } = $props();
</script>

<div class="min-h-screen flex flex-col">
	<header class="border-b border-[var(--border)] px-6 py-4 flex items-center justify-between">
		<div class="flex items-center gap-3">
			<div class="w-8 h-8 rounded-lg bg-[var(--accent)] flex items-center justify-center text-white font-bold text-sm">B</div>
			<span class="font-semibold text-lg">Burrow</span>
		</div>
		<nav class="flex gap-1">
			<a href="/" class="px-3 py-1.5 rounded text-sm hover:bg-[var(--bg-card)] transition-colors">Connect</a>
			<a href="/servers" class="px-3 py-1.5 rounded text-sm hover:bg-[var(--bg-card)] transition-colors">Servers</a>
			<a href="/settings" class="px-3 py-1.5 rounded text-sm hover:bg-[var(--bg-card)] transition-colors">Settings</a>
		</nav>
	</header>

	<main class="flex-1 p-6 max-w-2xl mx-auto w-full">
		{@render children()}
	</main>
</div>
