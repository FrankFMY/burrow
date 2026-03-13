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

<div class="min-h-screen flex items-center justify-center bg-[var(--bg-primary)] px-4">
	<div class="absolute inset-0 overflow-hidden pointer-events-none">
		<div class="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl"></div>
		<div class="absolute bottom-1/4 right-1/4 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl"></div>
	</div>

	<form onsubmit={handleLogin} class="bg-[var(--bg-secondary)] p-8 rounded-2xl border border-[var(--border)] w-full max-w-sm animate-in-scale relative shadow-2xl shadow-black/20">
		<div class="flex justify-center mb-6">
			<div class="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center text-white font-bold text-2xl shadow-lg shadow-blue-500/30">B</div>
		</div>
		<h1 class="text-xl font-bold mb-2 text-center">Burrow Admin</h1>
		<p class="text-sm text-[var(--text-secondary)] text-center mb-6">Sign in to manage your VPN</p>

		{#if error}
			<div class="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-2.5 rounded-lg mb-4 text-sm flex items-center gap-2 animate-in">
				<svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
				</svg>
				{error}
			</div>
		{/if}

		<div class="relative mb-4">
			<svg class="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
				<path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
			</svg>
			<input
				type="password"
				bind:value={password}
				placeholder="Admin password"
				class="w-full pl-10 pr-3 py-2.5 bg-[var(--bg-primary)] border border-[var(--border)] rounded-lg text-[var(--text-primary)] outline-none transition-all"
				required
			/>
		</div>

		<button
			type="submit"
			disabled={loading}
			class="w-full py-2.5 bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 text-white rounded-lg font-medium transition-all disabled:opacity-50 cursor-pointer active:scale-[0.98] shadow-lg shadow-blue-500/20"
		>
			{#if loading}
				<span class="flex items-center justify-center gap-2">
					<span class="spinner"></span>
					Signing in...
				</span>
			{:else}
				Sign in
			{/if}
		</button>
	</form>
</div>
