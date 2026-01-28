<script lang="ts">
import { onMount } from 'svelte';
import { adminApi, getErrorMessage, type AdminNetwork } from '$lib/api';

let networks: AdminNetwork[] = [];
let total = 0;
let offset = 0;
let limit = 20;
let search = '';
let loading = true;
let error = '';

async function loadNetworks() {
    loading = true;
    error = '';
    try {
        const result = await adminApi.listNetworks({ offset, limit, search: search || undefined });
        networks = result.networks;
        total = result.total;
    } catch (e) {
        error = getErrorMessage(e);
    } finally {
        loading = false;
    }
}

onMount(loadNetworks);

async function handleSearch() {
    offset = 0;
    await loadNetworks();
}

async function nextPage() {
    if (offset + limit < total) {
        offset += limit;
        await loadNetworks();
    }
}

async function prevPage() {
    if (offset > 0) {
        offset = Math.max(0, offset - limit);
        await loadNetworks();
    }
}

function formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    });
}
</script>

<div class="networks-page">
    <div class="header">
        <h1>All Networks</h1>
        <div class="search-bar">
            <input
                type="text"
                placeholder="Search by name..."
                bind:value={search}
                on:keyup={(e) => e.key === 'Enter' && handleSearch()}
            />
            <button on:click={handleSearch}>Search</button>
        </div>
    </div>

    {#if error}
        <div class="error">{error}</div>
    {/if}

    {#if loading}
        <div class="loading">Loading networks...</div>
    {:else}
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>CIDR</th>
                        <th>Owner</th>
                        <th>Nodes</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    {#each networks as network}
                        <tr>
                            <td class="name">{network.name}</td>
                            <td class="cidr">{network.cidr}</td>
                            <td class="owner">
                                {#if network.owner_email}
                                    {network.owner_email}
                                {:else}
                                    <span class="no-owner">No owner</span>
                                {/if}
                            </td>
                            <td class="nodes">
                                <span class="node-count">{network.node_count}</span>
                            </td>
                            <td>{formatDate(network.created_at)}</td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        </div>

        <div class="pagination">
            <button on:click={prevPage} disabled={offset === 0}>← Previous</button>
            <span>Showing {offset + 1}-{Math.min(offset + limit, total)} of {total}</span>
            <button on:click={nextPage} disabled={offset + limit >= total}>Next →</button>
        </div>
    {/if}
</div>

<style>
    .networks-page h1 {
        color: #fff;
        margin-bottom: 1.5rem;
    }

    .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 1.5rem;
        flex-wrap: wrap;
        gap: 1rem;
    }

    .search-bar {
        display: flex;
        gap: 0.5rem;
    }

    .search-bar input {
        padding: 0.5rem 1rem;
        border: 1px solid #2a2a3e;
        border-radius: 0.5rem;
        background: #1a1a2e;
        color: #fff;
        width: 250px;
    }

    .search-bar button {
        padding: 0.5rem 1rem;
        background: #7c3aed;
        color: #fff;
        border: none;
        border-radius: 0.5rem;
        cursor: pointer;
    }

    .error {
        background: rgba(239, 68, 68, 0.1);
        color: #f87171;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }

    .loading {
        text-align: center;
        padding: 2rem;
        color: #a0a0a0;
    }

    .table-container {
        overflow-x: auto;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        background: #1a1a2e;
        border-radius: 0.5rem;
        overflow: hidden;
    }

    th, td {
        padding: 1rem;
        text-align: left;
        border-bottom: 1px solid #2a2a3e;
    }

    th {
        background: #2a2a3e;
        color: #a0a0a0;
        font-weight: 500;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    td {
        color: #fff;
    }

    .name {
        font-weight: 500;
    }

    .cidr {
        font-family: monospace;
        color: #7c3aed;
    }

    .owner {
        font-size: 0.875rem;
    }

    .no-owner {
        color: #4a4a5a;
        font-style: italic;
    }

    .node-count {
        display: inline-block;
        background: #2a2a3e;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.875rem;
    }

    .pagination {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 1rem;
        margin-top: 1.5rem;
        color: #a0a0a0;
    }

    .pagination button {
        padding: 0.5rem 1rem;
        background: #2a2a3e;
        color: #fff;
        border: none;
        border-radius: 0.5rem;
        cursor: pointer;
    }

    .pagination button:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
</style>
