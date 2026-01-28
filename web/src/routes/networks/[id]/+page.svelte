<script lang="ts">
import { onDestroy, onMount } from 'svelte';
import { goto } from '$app/navigation';
import { page } from '$app/stores';
import { getErrorMessage, networksApi } from '$lib/api';
import { isAuthenticated } from '$lib/stores/auth';
import { isWsConnected, websocket } from '$lib/stores/websocket';

interface Network {
    id: string;
    name: string;
    cidr: string;
    created_at: string;
}

interface Node {
    id: string;
    name: string;
    public_key: string;
    mesh_ip: string;
    endpoint?: string;
    status: string;
    created_at: string;
    last_seen?: string;
}

let network: Network | null = null;
let nodes: Node[] = [];
let inviteCode = '';
let loading = true;
let copied = false;
let error = '';

$: networkId = $page.params.id;

// Handle WebSocket events
$: if ($websocket.lastEvent) {
    const event = $websocket.lastEvent;
    const eventData = event.data ?? {};
    if (eventData.network_id === networkId) {
        const { node_id, name: nodeName, mesh_ip, status } = eventData;
        switch (event.type) {
            case 'NodeJoined':
                if (node_id && nodeName && mesh_ip) {
                    nodes = [
                        ...nodes,
                        {
                            id: node_id,
                            name: nodeName,
                            public_key: '',
                            mesh_ip: mesh_ip,
                            status: 'online',
                            created_at: new Date().toISOString(),
                        },
                    ];
                }
                break;
            case 'NodeStatus':
                if (node_id && status) {
                    nodes = nodes.map((n) => (n.id === node_id ? { ...n, status } : n));
                }
                break;
            case 'NodeLeft':
                if (node_id) {
                    nodes = nodes.filter((n) => n.id !== node_id);
                }
                break;
        }
    }
}

onMount(async () => {
    // Auth guard - redirect to login if not authenticated
    if (!$isAuthenticated) {
        goto('/login');
        return;
    }
    if (!networkId) {
        error = 'Network ID not found';
        loading = false;
        return;
    }
    try {
        const [netData, nodesData] = await Promise.all([
            networksApi.get(networkId),
            networksApi.listNodes(networkId),
        ]);
        network = netData;
        nodes = nodesData;

        // Connect to WebSocket for this network
        websocket.connect(networkId);
    } catch (e: unknown) {
        error = getErrorMessage(e);
    }
    loading = false;
});

onDestroy(() => {
    websocket.disconnect();
});

async function generateInvite() {
    if (!networkId) return;
    try {
        const data = await networksApi.createInvite(networkId);
        inviteCode = data.code;
    } catch (e: unknown) {
        error = getErrorMessage(e);
    }
}

async function copyCode() {
    await navigator.clipboard.writeText(`burrow join ${inviteCode}`);
    copied = true;
    setTimeout(() => {
        copied = false;
    }, 2000);
}
</script>

<svelte:head><title>{network?.name || 'Network'} - Burrow</title></svelte:head>

{#if loading}
    <p>Loading...</p>
{:else if error}
    <div class="error">{error}</div>
{:else if network}
    <div class="page">
        <a href="/networks" class="back">← Back to networks</a>
        <div class="header">
            <h1>{network.name}</h1>
            <div class="connection-status" class:connected={$isWsConnected}>
                <span class="dot"></span>
                {$isWsConnected ? 'Live' : 'Connecting...'}
            </div>
        </div>
        <code class="cidr">{network.cidr}</code>

        <section class="invite">
            <h2>Invite Devices</h2>
            {#if inviteCode}
                <div class="code-box">
                    <code class="big">{inviteCode}</code>
                    <button on:click={copyCode}>{copied ? 'Copied!' : 'Copy'}</button>
                </div>
                <div class="command">
                    <code>burrow join {inviteCode}</code>
                </div>
            {:else}
                <p>Generate a code to add devices to this network.</p>
                <button on:click={generateInvite}>Generate Invite Code</button>
            {/if}
        </section>

        <section class="nodes">
            <h2>Nodes ({nodes.length})</h2>
            {#if nodes.length === 0}
                <p class="empty">No nodes yet. Generate an invite code and run <code>burrow join CODE</code></p>
            {:else}
                <div class="node-list">
                    {#each nodes as node (node.id)}
                        <div class="node" class:offline={node.status !== 'online'}>
                            <div class="node-header">
                                <span class="name">{node.name}</span>
                                <span class="status" class:online={node.status === 'online'}>
                                    {node.status}
                                </span>
                            </div>
                            <div class="node-info">
                                <span>Mesh IP: <code>{node.mesh_ip}</code></span>
                                {#if node.endpoint}
                                    <span>Endpoint: <code>{node.endpoint}</code></span>
                                {/if}
                                {#if node.last_seen}
                                    <span class="last-seen">
                                        Last seen: {new Date(node.last_seen).toLocaleString()}
                                    </span>
                                {/if}
                            </div>
                        </div>
                    {/each}
                </div>
            {/if}
        </section>
    </div>
{/if}

<style>
    .page { max-width: 800px; margin: 0 auto; }
    .back { color: #a0a0a0; text-decoration: none; }
    .back:hover { color: #7c3aed; }

    .header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin: 0.5rem 0;
    }

    h1 { margin: 0; }

    .connection-status {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.875rem;
        color: #888;
    }

    .connection-status .dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #888;
    }

    .connection-status.connected {
        color: #10b981;
    }

    .connection-status.connected .dot {
        background: #10b981;
        animation: pulse 2s infinite;
    }

    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }

    .cidr { color: #a0a0a0; font-size: 1.1rem; }

    section {
        background: #16213e;
        padding: 1.5rem;
        border-radius: 1rem;
        margin-top: 2rem;
    }

    section h2 { margin-bottom: 1rem; color: #fff; }
    section p { color: #a0a0a0; margin-bottom: 1rem; }

    .code-box {
        display: flex;
        align-items: center;
        gap: 1rem;
        background: #0f0f1a;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }

    .big {
        font-size: 1.5rem;
        font-weight: bold;
        color: #7c3aed;
        letter-spacing: 0.1em;
    }

    .command {
        background: #0f0f1a;
        padding: 0.75rem 1rem;
        border-radius: 0.5rem;
    }

    .command code { color: #10b981; }

    .error {
        background: #ff4444;
        color: #fff;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }

    .node-list {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
    }

    .node {
        background: #1a1a2e;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 3px solid #10b981;
        transition: all 0.3s ease;
    }

    .node.offline {
        border-left-color: #ef4444;
        opacity: 0.7;
    }

    .node-header {
        display: flex;
        justify-content: space-between;
        margin-bottom: 0.5rem;
    }

    .name { font-weight: 600; color: #fff; }

    .status {
        padding: 0.25rem 0.75rem;
        border-radius: 1rem;
        font-size: 0.8rem;
        background: #ef4444;
        color: #fff;
    }

    .status.online { background: #10b981; }

    .node-info {
        color: #a0a0a0;
        font-size: 0.9rem;
        display: flex;
        flex-direction: column;
        gap: 0.25rem;
    }

    .node-info code {
        color: #7c3aed;
    }

    .last-seen {
        font-size: 0.8rem;
        color: #666;
    }

    .empty {
        text-align: center;
        padding: 2rem;
    }

    .empty code { color: #10b981; }

    button {
        padding: 0.75rem 1.5rem;
        border: none;
        border-radius: 0.5rem;
        background: #7c3aed;
        color: #fff;
        cursor: pointer;
        font-size: 1rem;
    }

    button:hover {
        background: #6d28d9;
    }
</style>
