<script lang="ts">
    import { onMount } from 'svelte';
    import { networksApi } from '$lib/api';

    let networks: { id: string; name: string; cidr: string; created_at: string }[] = [];
    let loading = true;
    let showCreate = false;
    let newName = '';
    let error = '';

    onMount(async () => {
        await loadNetworks();
    });

    async function loadNetworks() {
        loading = true;
        try {
            networks = await networksApi.list();
        } catch (e: any) {
            error = e.message;
        }
        loading = false;
    }

    async function createNetwork() {
        if (!newName.trim()) return;
        error = '';
        try {
            await networksApi.create({ name: newName });
            newName = '';
            showCreate = false;
            await loadNetworks();
        } catch (e: any) {
            error = e.message;
        }
    }
</script>

<svelte:head><title>Networks - Burrow</title></svelte:head>

<div class="page">
    <div class="header">
        <h1>Networks</h1>
        <button on:click={() => showCreate = true}>+ Create Network</button>
    </div>

    {#if showCreate}
        <div class="modal-bg" on:click={() => showCreate = false}>
            <div class="modal" on:click|stopPropagation>
                <h2>Create Network</h2>
                <form on:submit|preventDefault={createNetwork}>
                    <input type="text" bind:value={newName} placeholder="Network name" autofocus />
                    <div class="actions">
                        <button type="button" class="secondary" on:click={() => showCreate = false}>Cancel</button>
                        <button type="submit">Create</button>
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
            <button on:click={() => showCreate = true}>Create your first network</button>
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
</style>
