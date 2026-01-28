<script lang="ts">
import { onMount } from 'svelte';
import { goto } from '$app/navigation';
import { getErrorMessage, networksApi } from '$lib/api';
import { isAuthenticated } from '$lib/stores/auth';

let networks: { id: string; name: string; cidr: string; created_at: string }[] = [];
let loading = true;
let showCreate = false;
let newName = '';
let error = '';
let creating = false;
let formError = '';

onMount(async () => {
    // Auth guard - redirect to login if not authenticated
    if (!$isAuthenticated) {
        goto('/login');
        return;
    }
    await loadNetworks();
});

function openCreateModal() {
    newName = '';
    formError = '';
    showCreate = true;
}

function closeCreateModal() {
    showCreate = false;
    newName = '';
    formError = '';
}

async function loadNetworks() {
    loading = true;
    try {
        networks = await networksApi.list();
    } catch (e: unknown) {
        error = getErrorMessage(e);
    }
    loading = false;
}

async function createNetwork() {
    if (!newName.trim() || creating) return;
    formError = '';
    creating = true;
    try {
        await networksApi.create({ name: newName });
        closeCreateModal();
        await loadNetworks();
    } catch (e: unknown) {
        formError = getErrorMessage(e);
    } finally {
        creating = false;
    }
}
</script>

<svelte:head><title>Networks - Burrow</title></svelte:head>

<div class="page">
    <div class="header">
        <h1>Networks</h1>
        <button on:click={openCreateModal}>+ Create Network</button>
    </div>

    {#if showCreate}
        <!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
        <div class="modal-bg" role="presentation" on:click={closeCreateModal} on:keydown={(e) => e.key === 'Escape' && closeCreateModal()}>
            <!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
            <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title" tabindex="-1" on:click|stopPropagation on:keydown|stopPropagation>
                <h2 id="modal-title">Create Network</h2>
                {#if formError}
                    <p class="form-error">{formError}</p>
                {/if}
                <form on:submit|preventDefault={createNetwork}>
                    <!-- svelte-ignore a11y_autofocus -->
                    <input type="text" bind:value={newName} placeholder="Network name" autofocus />
                    <div class="actions">
                        <button type="button" class="secondary" on:click={closeCreateModal}>Cancel</button>
                        <button type="submit" disabled={creating}>{creating ? 'Creating...' : 'Create'}</button>
                    </div>
                </form>
            </div>
        </div>
    {/if}

    {#if loading}
        <p>Loading...</p>
    {:else if networks.length === 0}
        <div class="empty">
            <p>No networks yet</p>
            <button on:click={openCreateModal}>Create your first network</button>
        </div>
    {:else}
        <div class="list">
            {#each networks as net}
                <a href="/networks/{net.id}" class="item">
                    <span class="name">{net.name}</span>
                    <code>{net.cidr}</code>
                </a>
            {/each}
        </div>
    {/if}
</div>

<style>
    .page { max-width: 800px; margin: 0 auto; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
    .list { display: flex; flex-direction: column; gap: 0.5rem; }
    .item {
        background: #16213e;
        padding: 1rem 1.5rem;
        border-radius: 0.5rem;
        display: flex;
        justify-content: space-between;
        text-decoration: none;
        color: inherit;
    }
    .item:hover { background: #1a1a2e; }
    .name { font-weight: 600; }
    code { color: #a0a0a0; }
    .empty { text-align: center; padding: 4rem; background: #16213e; border-radius: 1rem; }
    .empty p { margin-bottom: 1rem; color: #a0a0a0; }
    .modal-bg {
        position: fixed;
        inset: 0;
        background: rgba(0,0,0,0.7);
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .modal { background: #1a1a2e; padding: 2rem; border-radius: 1rem; width: 100%; max-width: 400px; }
    .modal h2 { margin-bottom: 1.5rem; }
    .modal input { width: 100%; margin-bottom: 1rem; }
    .actions { display: flex; gap: 1rem; justify-content: flex-end; }
    .secondary { background: transparent; border: 1px solid #666; }
    .form-error { color: #ef4444; margin-bottom: 1rem; padding: 0.5rem; background: rgba(239, 68, 68, 0.1); border-radius: 0.25rem; }
</style>
