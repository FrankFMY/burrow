<script lang="ts">
    import { onMount } from 'svelte';
    import { isAuthenticated } from '$lib/stores/auth';
    import { networksApi } from '$lib/api';

    let networks: { id: string; name: string; cidr: string; created_at: string }[] = [];
    let stats = { networks: 0, nodes: 0 };
    let loading = true;

    onMount(async () => {
        if ($isAuthenticated) {
            try {
                networks = await networksApi.list();
                stats.networks = networks.length;
            } catch (e) {
                console.error('Failed to load networks:', e);
            }
        }
        loading = false;
    });
</script>

<svelte:head><title>Burrow - Dashboard</title></svelte:head>

{#if !$isAuthenticated}
    <div class="welcome">
        <div class="hero">
            <h1>🕳️ Burrow</h1>
            <p class="tagline">Simple, fast, open-source mesh VPN</p>
            <div class="features">
                <div class="feature">🚀 Built on WireGuard</div>
                <div class="feature">🔒 End-to-end encryption</div>
                <div class="feature">🌐 Mesh networking</div>
                <div class="feature">🔄 NAT traversal</div>
            </div>
            <div class="cta">
                <a href="/register" class="btn primary">Get Started</a>
                <a href="/login" class="btn secondary">Sign In</a>
            </div>
        </div>
    </div>
{:else}
    <div class="dashboard">
        <h1>Dashboard</h1>
        {#if loading}
            <p>Loading...</p>
        {:else}
            <div class="stats">
                <div class="card"><div class="value">{stats.networks}</div><div class="label">Networks</div></div>
                <div class="card"><div class="value">{stats.nodes}</div><div class="label">Nodes</div></div>
            </div>
            <section>
                <h2>Networks</h2>
                {#if networks.length === 0}
                    <p class="empty">No networks yet. <a href="/networks">Create one!</a></p>
                {:else}
                    <div class="grid">
                        {#each networks as net}
                            <a href="/networks/{net.id}" class="network-card">
                                <h3>{net.name}</h3>
                                <code>{net.cidr}</code>
                            </a>
                        {/each}
                    </div>
                {/if}
            </section>
        {/if}
    </div>
{/if}

<style>
    /* Welcome page */
    .welcome {
        min-height: 70vh;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .hero {
        text-align: center;
        max-width: 600px;
    }
    .hero h1 {
        font-size: 4rem;
        margin: 0 0 1rem;
    }
    .tagline {
        font-size: 1.5rem;
        color: #a0a0a0;
        margin: 0 0 2.5rem;
    }
    .features {
        display: flex;
        flex-wrap: wrap;
        justify-content: center;
        gap: 1rem;
        margin-bottom: 2.5rem;
    }
    .feature {
        background: #16213e;
        padding: 0.75rem 1.25rem;
        border-radius: 2rem;
        font-size: 0.9rem;
    }
    .cta {
        display: flex;
        gap: 1rem;
        justify-content: center;
    }
    .btn {
        padding: 0.875rem 2rem;
        border-radius: 0.5rem;
        text-decoration: none;
        font-weight: 500;
        font-size: 1rem;
    }
    .btn.primary {
        background: #7c3aed;
        color: white;
    }
    .btn.primary:hover {
        background: #6d28d9;
    }
    .btn.secondary {
        background: transparent;
        border: 1px solid #4a4a5a;
        color: #a0a0a0;
    }
    .btn.secondary:hover {
        border-color: #7c3aed;
        color: #fff;
    }

    /* Dashboard */
    .dashboard { max-width: 1000px; margin: 0 auto; }
    .dashboard h1 { margin-bottom: 2rem; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .card { background: #16213e; padding: 1.5rem; border-radius: 1rem; text-align: center; }
    .value { font-size: 2.5rem; font-weight: bold; color: #7c3aed; }
    .label { color: #a0a0a0; margin-top: 0.5rem; }
    section { margin-top: 2rem; }
    h2 { margin-bottom: 1rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 1rem; }
    .network-card { background: #16213e; padding: 1.5rem; border-radius: 0.75rem; text-decoration: none; color: inherit; }
    .network-card:hover { background: #1a1a2e; }
    .network-card h3 { margin-bottom: 0.5rem; }
    .network-card code { color: #a0a0a0; }
    .empty { color: #a0a0a0; }
    .empty a { color: #7c3aed; }
</style>
