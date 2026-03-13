<script lang="ts">
	import { login } from '$lib/api';

	let password = $state('');
	let error = $state('');
	let loading = $state(false);

	async function handleLogin(e: Event) {
		e.preventDefault();
		error = '';
		loading = true;
		try {
			await login(password);
			window.location.href = '/admin';
		} catch {
			error = 'Invalid password';
		} finally {
			loading = false;
		}
	}
</script>

<div class="min-h-screen flex items-center justify-center bg-[var(--bg-primary)]">
	<form onsubmit={handleLogin} class="bg-[var(--bg-secondary)] p-8 rounded-lg border border-[var(--border)] w-80">
		<h1 class="text-xl font-bold mb-6 text-center text-[var(--accent)]">Burrow Admin</h1>

		{#if error}
			<div class="bg-red-500/10 border border-red-500/30 text-red-400 px-3 py-2 rounded mb-4 text-sm">{error}</div>
		{/if}

		<input
			type="password"
			bind:value={password}
			placeholder="Admin password"
			class="w-full px-3 py-2 bg-[var(--bg-primary)] border border-[var(--border)] rounded text-[var(--text-primary)] mb-4 outline-none focus:border-[var(--accent)]"
			required
		/>

		<button
			type="submit"
			disabled={loading}
			class="w-full py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded font-medium transition-colors disabled:opacity-50 cursor-pointer"
		>
			{loading ? 'Signing in...' : 'Sign in'}
		</button>
	</form>
</div>
