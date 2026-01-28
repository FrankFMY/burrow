<script lang="ts">
import { onMount } from 'svelte';
import { goto } from '$app/navigation';
import { auth, isAuthenticated } from '$lib/stores/auth';
import { page } from '$app/stores';

onMount(() => {
    // Redirect non-admins
    if (!$isAuthenticated || $auth.user?.role !== 'admin') {
        goto('/');
    }
});

$: isActive = (path: string) => $page.url.pathname === path || $page.url.pathname.startsWith(path + '/');
</script>

{#if $auth.user?.role === 'admin'}
<div class="admin-layout">
    <aside class="sidebar">
        <h2>Admin Panel</h2>
        <nav>
            <a href="/admin" class:active={$page.url.pathname === '/admin'}>
                <span class="icon">📊</span> Dashboard
            </a>
            <a href="/admin/users" class:active={isActive('/admin/users')}>
                <span class="icon">👥</span> Users
            </a>
            <a href="/admin/networks" class:active={isActive('/admin/networks')}>
                <span class="icon">🌐</span> Networks
            </a>
            <a href="/admin/audit" class:active={isActive('/admin/audit')}>
                <span class="icon">📋</span> Audit Log
            </a>
        </nav>
    </aside>
    <div class="content">
        <slot />
    </div>
</div>
{:else}
<div class="loading">Checking permissions...</div>
{/if}

<style>
    .admin-layout {
        display: flex;
        min-height: calc(100vh - 80px);
        margin: -2rem;
    }

    .sidebar {
        width: 240px;
        background: #1a1a2e;
        padding: 1.5rem;
        border-right: 1px solid #2a2a3e;
    }

    .sidebar h2 {
        color: #7c3aed;
        font-size: 1rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 1.5rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid #2a2a3e;
    }

    .sidebar nav {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }

    .sidebar nav a {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 0.75rem 1rem;
        color: #a0a0a0;
        text-decoration: none;
        border-radius: 0.5rem;
        transition: all 0.2s;
    }

    .sidebar nav a:hover {
        background: #2a2a3e;
        color: #fff;
    }

    .sidebar nav a.active {
        background: #7c3aed;
        color: #fff;
    }

    .icon {
        font-size: 1.1rem;
    }

    .content {
        flex: 1;
        padding: 2rem;
        overflow-y: auto;
    }

    .loading {
        display: flex;
        justify-content: center;
        align-items: center;
        height: 50vh;
        color: #a0a0a0;
    }
</style>
