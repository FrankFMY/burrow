<script lang="ts">
import { onMount } from 'svelte';
import { adminApi, getErrorMessage, type SystemStats } from '$lib/api';

let stats: SystemStats | null = null;
let loading = true;
let error = '';

onMount(async () => {
    try {
        stats = await adminApi.getStats();
    } catch (e) {
        error = getErrorMessage(e);
    } finally {
        loading = false;
    }
});

function formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    return parts.join(' ') || '< 1m';
}
</script>

<div class="dashboard">
    <h1>Admin Dashboard</h1>

    {#if loading}
        <div class="loading">Loading statistics...</div>
    {:else if error}
        <div class="error">{error}</div>
    {:else if stats}
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-icon">👥</span>
                    <span class="stat-title">Users</span>
                </div>
                <div class="stat-value">{stats.total_users}</div>
                <div class="stat-details">
                    <span>{stats.verified_users} verified</span>
                    <span class="admin-badge">{stats.admin_users} admins</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-icon">🌐</span>
                    <span class="stat-title">Networks</span>
                </div>
                <div class="stat-value">{stats.total_networks}</div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-icon">🖥️</span>
                    <span class="stat-title">Nodes</span>
                </div>
                <div class="stat-value">{stats.total_nodes}</div>
                <div class="stat-details">
                    <span class="online">{stats.online_nodes} online</span>
                    <span class="offline">{stats.offline_nodes} offline</span>
                    <span class="pending">{stats.pending_nodes} pending</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-icon">🔐</span>
                    <span class="stat-title">Sessions</span>
                </div>
                <div class="stat-value">{stats.active_sessions}</div>
                <div class="stat-details">
                    <span>Active refresh tokens</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-icon">📈</span>
                    <span class="stat-title">Today</span>
                </div>
                <div class="stat-value">{stats.logins_today}</div>
                <div class="stat-details">
                    <span>Logins</span>
                    <span>{stats.registrations_today} registrations</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-icon">⚙️</span>
                    <span class="stat-title">Server</span>
                </div>
                <div class="stat-value">v{stats.server_version}</div>
                <div class="stat-details">
                    <span>Uptime: {formatUptime(stats.uptime_seconds)}</span>
                </div>
            </div>
        </div>

        <div class="quick-actions">
            <h2>Quick Actions</h2>
            <div class="actions">
                <a href="/admin/users" class="action-btn">
                    <span>👥</span> Manage Users
                </a>
                <a href="/admin/networks" class="action-btn">
                    <span>🌐</span> View Networks
                </a>
                <a href="/admin/audit" class="action-btn">
                    <span>📋</span> Audit Log
                </a>
            </div>
        </div>
    {/if}
</div>

<style>
    .dashboard h1 {
        color: #fff;
        margin-bottom: 2rem;
    }

    .loading, .error {
        text-align: center;
        padding: 2rem;
        color: #a0a0a0;
    }

    .error {
        color: #f87171;
        background: rgba(239, 68, 68, 0.1);
        border-radius: 0.5rem;
    }

    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
        gap: 1.5rem;
        margin-bottom: 3rem;
    }

    .stat-card {
        background: #1a1a2e;
        border-radius: 1rem;
        padding: 1.5rem;
        border: 1px solid #2a2a3e;
    }

    .stat-header {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-bottom: 1rem;
    }

    .stat-icon {
        font-size: 1.25rem;
    }

    .stat-title {
        color: #a0a0a0;
        font-size: 0.875rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .stat-value {
        font-size: 2.5rem;
        font-weight: bold;
        color: #fff;
        margin-bottom: 0.5rem;
    }

    .stat-details {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
        font-size: 0.75rem;
        color: #a0a0a0;
    }

    .stat-details span {
        background: #2a2a3e;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
    }

    .stat-details .online { color: #4ade80; }
    .stat-details .offline { color: #f87171; }
    .stat-details .pending { color: #facc15; }
    .stat-details .admin-badge { color: #7c3aed; }

    .quick-actions h2 {
        color: #fff;
        font-size: 1.25rem;
        margin-bottom: 1rem;
    }

    .actions {
        display: flex;
        gap: 1rem;
        flex-wrap: wrap;
    }

    .action-btn {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 1rem 1.5rem;
        background: #1a1a2e;
        border: 1px solid #2a2a3e;
        border-radius: 0.5rem;
        color: #fff;
        text-decoration: none;
        transition: all 0.2s;
    }

    .action-btn:hover {
        border-color: #7c3aed;
        background: #2a2a3e;
    }
</style>
