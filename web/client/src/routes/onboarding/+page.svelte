<script lang="ts">
	import { addServer, connect } from '$lib/api';
	import { goto } from '$app/navigation';
	import { t } from '$lib/i18n.svelte';

	let step = $state(0);
	let inviteLink = $state('');
	let loading = $state(false);
	let error = $state('');

	async function handleAddAndConnect() {
		if (!inviteLink.trim()) return;
		loading = true;
		error = '';
		try {
			await addServer(inviteLink.trim());
			step = 2;
			try {
				await connect(undefined, false, true);
			} catch {}
			goto('/');
		} catch (e: any) {
			error = e.message;
		} finally {
			loading = false;
		}
	}
</script>

<div class="min-h-[70vh] flex flex-col items-center justify-center px-4">
	{#if step === 0}
		<div class="text-center animate-in-scale max-w-sm">
			<div class="w-20 h-20 mx-auto mb-6 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-2xl shadow-indigo-500/30">
				<svg class="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
					<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
				</svg>
			</div>
			<h1 class="text-2xl font-bold mb-2">{t('onboarding.welcome')}</h1>
			<p class="text-[var(--text-secondary)] mb-8">{t('onboarding.subtitle')}</p>

			<div class="text-left space-y-4 mb-8">
				{#each [
					{ num: '1', text: t('onboarding.step1'), icon: 'M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m9.07-9.07l4.5-4.5a4.5 4.5 0 016.364 6.364l-1.757 1.757' },
					{ num: '2', text: t('onboarding.step2'), icon: 'M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9.75a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184' },
					{ num: '3', text: t('onboarding.step3'), icon: 'M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z' },
				] as item, i}
					<div class="flex items-start gap-3 animate-in" style="animation-delay: {(i + 1) * 150}ms; animation-fill-mode: both">
						<div class="w-8 h-8 rounded-full bg-[var(--accent-glow)] border border-[var(--accent)]/20 flex items-center justify-center shrink-0 text-[var(--accent)] text-sm font-semibold">{item.num}</div>
						<span class="text-sm text-[var(--text-secondary)] pt-1.5">{item.text}</span>
					</div>
				{/each}
			</div>

			<button
				onclick={() => step = 1}
				class="w-full py-3 px-6 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 text-white rounded-xl font-medium transition-all cursor-pointer active:scale-[0.98] shadow-lg shadow-indigo-500/25"
			>
				{t('onboarding.continue')}
			</button>

			<button
				onclick={() => goto('/')}
				class="mt-3 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
			>
				{t('onboarding.skip')}
			</button>
		</div>

	{:else if step === 1}
		<div class="w-full max-w-sm animate-in">
			<button
				onclick={() => step = 0}
				class="flex items-center gap-1 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] mb-6 transition-colors cursor-pointer"
			>
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M15 19l-7-7 7-7" />
				</svg>
				Back
			</button>

			<h2 class="text-xl font-bold mb-2">{t('onboarding.paste_label')}</h2>
			<p class="text-sm text-[var(--text-secondary)] mb-6">{t('onboarding.step2')}</p>

			{#if error}
				<div class="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-2.5 rounded-xl text-sm mb-4 animate-in">
					{error}
				</div>
			{/if}

			<form onsubmit={(e) => { e.preventDefault(); handleAddAndConnect(); }}>
				<input
					bind:value={inviteLink}
					placeholder="burrow://connect/..."
					class="w-full px-4 py-3 bg-[var(--bg-card)] border border-[var(--border)] rounded-xl text-[var(--text-primary)] outline-none transition-all font-mono text-sm mb-4"
					autofocus
					required
				/>

				<button
					type="submit"
					disabled={loading || !inviteLink.trim()}
					class="w-full py-3 px-6 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 text-white rounded-xl font-medium transition-all cursor-pointer active:scale-[0.98] shadow-lg shadow-indigo-500/25 disabled:opacity-50"
				>
					{#if loading}
						<span class="flex items-center justify-center gap-2">
							<span class="spinner"></span>
							{t('status.connecting')}
						</span>
					{:else}
						{t('onboarding.continue')}
					{/if}
				</button>
			</form>
		</div>

	{:else}
		<div class="text-center animate-in-scale">
			<div class="w-16 h-16 mx-auto mb-4 rounded-full bg-[var(--success)]/10 border border-[var(--success)]/20 flex items-center justify-center">
				<svg class="w-8 h-8 text-[var(--success)]" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
				</svg>
			</div>
			<p class="text-lg font-medium">{t('status.connected')}</p>
			<p class="text-sm text-[var(--text-secondary)] mt-1">Redirecting...</p>
		</div>
	{/if}
</div>
