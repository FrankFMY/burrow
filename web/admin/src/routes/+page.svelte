<script lang="ts">
	import { getStats, formatBytes } from '$lib/api';
	import { onMount } from 'svelte';

	let stats = $state<any>(null);
	let error = $state('');

	onMount(async () => {
		try {
			stats = await getStats();
		} catch {
			error = 'Failed to load stats';
		}
	});
</script>

<h2 class="text-xl md:text-2xl font-bold mb-4 md:mb-6">Dashboard</h2>

{#if error}
	<div class="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-lg text-sm flex items-center gap-2 animate-in">
		<svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
			<path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
		</svg>
		{error}
	</div>
{:else if stats}
	<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-4 mb-6 md:mb-8">
		<div class="stat-card animate-in stagger-1" style="animation-fill-mode:both">
			<div class="flex items-center gap-2 text-[var(--text-secondary)] text-xs md:text-sm mb-2">
				<svg class="w-4 h-4 text-[var(--success)]" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728m-9.9-2.829a5 5 0 010-7.07m7.072 0a5 5 0 010 7.07M13 12a1 1 0 11-2 0 1 1 0 012 0z" />
				</svg>
				Active Clients
			</div>
			<div class="text-3xl md:text-4xl font-bold text-[var(--success)]">{stats.active_clients}</div>
		</div>
		<div class="stat-card animate-in stagger-2" style="animation-fill-mode:both">
			<div class="flex items-center gap-2 text-[var(--text-secondary)] text-xs md:text-sm mb-2">
				<svg class="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M7 11l5-5m0 0l5 5m-5-5v12" />
				</svg>
				Total Upload
			</div>
			<div class="text-2xl md:text-3xl font-bold">{formatBytes(stats.total_bytes_up)}</div>
		</div>
		<div class="stat-card animate-in stagger-3" style="animation-fill-mode:both">
			<div class="flex items-center gap-2 text-[var(--text-secondary)] text-xs md:text-sm mb-2">
				<svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M17 13l-5 5m0 0l-5-5m5 5V6" />
				</svg>
				Total Download
			</div>
			<div class="text-2xl md:text-3xl font-bold">{formatBytes(stats.total_bytes_down)}</div>
		</div>
	</div>

	<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-4">
		<div class="stat-card animate-in stagger-4" style="animation-fill-mode:both">
			<div class="flex items-center gap-2 text-[var(--text-secondary)] text-xs md:text-sm mb-2">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
				</svg>
				Total Clients
			</div>
			<div class="text-xl md:text-2xl font-bold">{stats.total_clients}</div>
		</div>
		<div class="stat-card animate-in stagger-5" style="animation-fill-mode:both">
			<div class="flex items-center gap-2 text-[var(--text-secondary)] text-xs md:text-sm mb-2">
				<svg class="w-4 h-4 text-[var(--danger)]" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
				</svg>
				Revoked
			</div>
			<div class="text-xl md:text-2xl font-bold text-[var(--danger)]">{stats.revoked_clients}</div>
		</div>
		<div class="stat-card animate-in stagger-5" style="animation-fill-mode:both">
			<div class="flex items-center gap-2 text-[var(--text-secondary)] text-xs md:text-sm mb-2">
				<svg class="w-4 h-4 text-[var(--accent)]" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
					<path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
				</svg>
				Connections
			</div>
			<div class="text-xl md:text-2xl font-bold">{stats.total_connections}</div>
		</div>
	</div>
{:else}
	<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-4 mb-6 md:mb-8">
		{#each [1,2,3] as _}
			<div class="stat-card">
				<div class="skeleton h-4 w-24 mb-3"></div>
				<div class="skeleton h-10 w-20"></div>
			</div>
		{/each}
	</div>
	<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-4">
		{#each [1,2,3] as _}
			<div class="stat-card">
				<div class="skeleton h-4 w-24 mb-3"></div>
				<div class="skeleton h-8 w-16"></div>
			</div>
		{/each}
	</div>
{/if}
