<script lang="ts">
import { onMount } from 'svelte';
import { adminApi, getErrorMessage, type AuditLogEntry } from '$lib/api';

let entries: AuditLogEntry[] = [];
let total = 0;
let offset = 0;
let limit = 50;
let eventTypeFilter = '';
let loading = true;
let error = '';

const eventTypes = [
    'user_registered',
    'user_login',
    'user_logout',
    'user_login_failed',
    'api_key_created',
    'api_key_revoked',
    'network_created',
    'network_deleted',
    'invite_created',
    'invite_used',
    'node_registered',
    'node_online',
    'node_offline',
    'user_role_changed',
    'user_updated',
    'user_deleted',
];

async function loadEntries() {
    loading = true;
    error = '';
    try {
        const result = await adminApi.listAuditLog({
            offset,
            limit,
            event_type: eventTypeFilter || undefined,
        });
        entries = result.entries;
        total = result.total;
    } catch (e) {
        error = getErrorMessage(e);
    } finally {
        loading = false;
    }
}

onMount(loadEntries);

async function applyFilter() {
    offset = 0;
    await loadEntries();
}

async function nextPage() {
    if (offset + limit < total) {
        offset += limit;
        await loadEntries();
    }
}

async function prevPage() {
    if (offset > 0) {
        offset = Math.max(0, offset - limit);
        await loadEntries();
    }
}

function formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function formatEventType(type: string): string {
    // Remove quotes if present (from JSON serialization)
    type = type.replace(/"/g, '');
    return type.split('_').map(word =>
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

function getEventIcon(type: string): string {
    type = type.replace(/"/g, '');
    const icons: Record<string, string> = {
        user_registered: '👤',
        user_login: '🔓',
        user_logout: '🔒',
        user_login_failed: '❌',
        api_key_created: '🔑',
        api_key_revoked: '🗑️',
        network_created: '🌐',
        network_deleted: '🗑️',
        invite_created: '📧',
        invite_used: '✅',
        node_registered: '🖥️',
        node_online: '🟢',
        node_offline: '🔴',
        user_role_changed: '👑',
        user_updated: '✏️',
        user_deleted: '🗑️',
    };
    return icons[type] || '📋';
}

function getEventClass(type: string): string {
    type = type.replace(/"/g, '');
    if (type.includes('failed') || type.includes('deleted') || type.includes('offline')) {
        return 'danger';
    }
    if (type.includes('created') || type.includes('registered') || type.includes('online')) {
        return 'success';
    }
    return '';
}
</script>

<div class="audit-page">
    <div class="header">
        <h1>Audit Log</h1>
        <div class="filter-bar">
            <select bind:value={eventTypeFilter} on:change={applyFilter}>
                <option value="">All Events</option>
                {#each eventTypes as type}
                    <option value={`"${type}"`}>{formatEventType(type)}</option>
                {/each}
            </select>
        </div>
    </div>

    {#if error}
        <div class="error">{error}</div>
    {/if}

    {#if loading}
        <div class="loading">Loading audit log...</div>
    {:else}
        <div class="entries">
            {#each entries as entry}
                <div class="entry" class:danger={getEventClass(entry.event_type) === 'danger'} class:success={getEventClass(entry.event_type) === 'success'}>
                    <div class="entry-icon">{getEventIcon(entry.event_type)}</div>
                    <div class="entry-content">
                        <div class="entry-header">
                            <span class="event-type">{formatEventType(entry.event_type)}</span>
                            <span class="timestamp">{formatDate(entry.created_at)}</span>
                        </div>
                        <div class="entry-details">
                            {#if entry.user_email}
                                <span class="detail">
                                    <span class="label">User:</span>
                                    <span class="value">{entry.user_email}</span>
                                </span>
                            {/if}
                            {#if entry.target_type && entry.target_id}
                                <span class="detail">
                                    <span class="label">{entry.target_type}:</span>
                                    <span class="value id">{entry.target_id.substring(0, 8)}...</span>
                                </span>
                            {/if}
                            {#if entry.ip_address}
                                <span class="detail">
                                    <span class="label">IP:</span>
                                    <span class="value">{entry.ip_address}</span>
                                </span>
                            {/if}
                        </div>
                        {#if entry.details}
                            <div class="entry-json">
                                <code>{JSON.stringify(entry.details, null, 2)}</code>
                            </div>
                        {/if}
                    </div>
                </div>
            {/each}
        </div>

        <div class="pagination">
            <button on:click={prevPage} disabled={offset === 0}>← Previous</button>
            <span>Showing {offset + 1}-{Math.min(offset + limit, total)} of {total}</span>
            <button on:click={nextPage} disabled={offset + limit >= total}>Next →</button>
        </div>
    {/if}
</div>

<style>
    .audit-page h1 {
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

    .filter-bar select {
        padding: 0.5rem 1rem;
        border: 1px solid #2a2a3e;
        border-radius: 0.5rem;
        background: #1a1a2e;
        color: #fff;
        min-width: 200px;
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

    .entries {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }

    .entry {
        display: flex;
        gap: 1rem;
        padding: 1rem;
        background: #1a1a2e;
        border-radius: 0.5rem;
        border-left: 3px solid #2a2a3e;
    }

    .entry.danger {
        border-left-color: #f87171;
    }

    .entry.success {
        border-left-color: #4ade80;
    }

    .entry-icon {
        font-size: 1.5rem;
        width: 2rem;
        text-align: center;
    }

    .entry-content {
        flex: 1;
        min-width: 0;
    }

    .entry-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.5rem;
    }

    .event-type {
        color: #fff;
        font-weight: 500;
    }

    .timestamp {
        color: #6a6a7a;
        font-size: 0.75rem;
    }

    .entry-details {
        display: flex;
        flex-wrap: wrap;
        gap: 1rem;
        font-size: 0.875rem;
    }

    .detail {
        display: flex;
        gap: 0.25rem;
    }

    .label {
        color: #6a6a7a;
    }

    .value {
        color: #a0a0a0;
    }

    .value.id {
        font-family: monospace;
        color: #7c3aed;
    }

    .entry-json {
        margin-top: 0.5rem;
        padding: 0.5rem;
        background: #0f0f1a;
        border-radius: 0.25rem;
        overflow-x: auto;
    }

    .entry-json code {
        font-size: 0.75rem;
        color: #a0a0a0;
        white-space: pre;
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
