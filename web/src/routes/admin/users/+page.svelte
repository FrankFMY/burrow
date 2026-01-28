<script lang="ts">
import { onMount } from 'svelte';
import { adminApi, getErrorMessage, type AdminUser } from '$lib/api';

let users: AdminUser[] = [];
let total = 0;
let offset = 0;
let limit = 20;
let search = '';
let loading = true;
let error = '';

let editingUser: AdminUser | null = null;
let editRole = '';
let editVerified = false;
let saving = false;

async function loadUsers() {
    loading = true;
    error = '';
    try {
        const result = await adminApi.listUsers({ offset, limit, search: search || undefined });
        users = result.users;
        total = result.total;
    } catch (e) {
        error = getErrorMessage(e);
    } finally {
        loading = false;
    }
}

onMount(loadUsers);

async function handleSearch() {
    offset = 0;
    await loadUsers();
}

async function nextPage() {
    if (offset + limit < total) {
        offset += limit;
        await loadUsers();
    }
}

async function prevPage() {
    if (offset > 0) {
        offset = Math.max(0, offset - limit);
        await loadUsers();
    }
}

function openEdit(user: AdminUser) {
    editingUser = user;
    editRole = user.role;
    editVerified = user.email_verified;
}

function closeEdit() {
    editingUser = null;
}

async function saveEdit() {
    if (!editingUser) return;

    saving = true;
    try {
        const updates: { role?: string; email_verified?: boolean } = {};
        if (editRole !== editingUser.role) updates.role = editRole;
        if (editVerified !== editingUser.email_verified) updates.email_verified = editVerified;

        if (Object.keys(updates).length > 0) {
            await adminApi.updateUser(editingUser.id, updates);
            await loadUsers();
        }
        closeEdit();
    } catch (e) {
        error = getErrorMessage(e);
    } finally {
        saving = false;
    }
}

async function deleteUser(user: AdminUser) {
    if (!confirm(`Are you sure you want to delete user "${user.email}"? This action cannot be undone.`)) {
        return;
    }

    try {
        await adminApi.deleteUser(user.id);
        await loadUsers();
    } catch (e) {
        error = getErrorMessage(e);
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

<div class="users-page">
    <div class="header">
        <h1>User Management</h1>
        <div class="search-bar">
            <input
                type="text"
                placeholder="Search by email or name..."
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
        <div class="loading">Loading users...</div>
    {:else}
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Name</th>
                        <th>Role</th>
                        <th>Verified</th>
                        <th>2FA</th>
                        <th>Created</th>
                        <th>Last Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {#each users as user}
                        <tr>
                            <td class="email">{user.email}</td>
                            <td>{user.name}</td>
                            <td>
                                <span class="badge" class:admin={user.role === 'admin'}>
                                    {user.role}
                                </span>
                            </td>
                            <td>
                                {#if user.email_verified}
                                    <span class="verified">✓</span>
                                {:else}
                                    <span class="unverified">✗</span>
                                {/if}
                            </td>
                            <td>
                                {#if user.totp_enabled}
                                    <span class="verified">✓</span>
                                {:else}
                                    <span class="disabled">-</span>
                                {/if}
                            </td>
                            <td>{formatDate(user.created_at)}</td>
                            <td>{user.last_login ? formatDate(user.last_login) : '-'}</td>
                            <td class="actions">
                                <button class="edit-btn" on:click={() => openEdit(user)}>Edit</button>
                                <button class="delete-btn" on:click={() => deleteUser(user)}>Delete</button>
                            </td>
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

{#if editingUser}
<div class="modal-overlay" on:click={closeEdit} on:keydown={(e) => e.key === 'Escape' && closeEdit()}>
    <div class="modal" on:click|stopPropagation role="dialog" aria-modal="true">
        <h2>Edit User</h2>
        <p class="user-email">{editingUser.email}</p>

        <div class="form-group">
            <label for="role">Role</label>
            <select id="role" bind:value={editRole}>
                <option value="user">User</option>
                <option value="admin">Admin</option>
            </select>
        </div>

        <div class="form-group">
            <label class="checkbox-label">
                <input type="checkbox" bind:checked={editVerified} />
                Email Verified
            </label>
        </div>

        <div class="modal-actions">
            <button class="cancel-btn" on:click={closeEdit}>Cancel</button>
            <button class="save-btn" on:click={saveEdit} disabled={saving}>
                {saving ? 'Saving...' : 'Save Changes'}
            </button>
        </div>
    </div>
</div>
{/if}

<style>
    .users-page h1 {
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

    .email {
        font-family: monospace;
    }

    .badge {
        display: inline-block;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.75rem;
        background: #2a2a3e;
        color: #a0a0a0;
    }

    .badge.admin {
        background: rgba(124, 58, 237, 0.2);
        color: #a78bfa;
    }

    .verified { color: #4ade80; }
    .unverified { color: #f87171; }
    .disabled { color: #4a4a5a; }

    .actions {
        display: flex;
        gap: 0.5rem;
    }

    .edit-btn, .delete-btn {
        padding: 0.25rem 0.5rem;
        border: none;
        border-radius: 0.25rem;
        cursor: pointer;
        font-size: 0.75rem;
    }

    .edit-btn {
        background: #2a2a3e;
        color: #fff;
    }

    .delete-btn {
        background: rgba(239, 68, 68, 0.2);
        color: #f87171;
    }

    .edit-btn:hover { background: #3a3a4e; }
    .delete-btn:hover { background: rgba(239, 68, 68, 0.3); }

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

    /* Modal */
    .modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
    }

    .modal {
        background: #1a1a2e;
        padding: 2rem;
        border-radius: 1rem;
        width: 400px;
        max-width: 90vw;
    }

    .modal h2 {
        color: #fff;
        margin-bottom: 0.5rem;
    }

    .user-email {
        color: #a0a0a0;
        font-family: monospace;
        margin-bottom: 1.5rem;
    }

    .form-group {
        margin-bottom: 1rem;
    }

    .form-group label {
        display: block;
        color: #a0a0a0;
        margin-bottom: 0.5rem;
        font-size: 0.875rem;
    }

    .form-group select {
        width: 100%;
        padding: 0.5rem;
        background: #2a2a3e;
        border: 1px solid #3a3a4e;
        border-radius: 0.5rem;
        color: #fff;
    }

    .checkbox-label {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        cursor: pointer;
    }

    .checkbox-label input {
        width: 1rem;
        height: 1rem;
    }

    .modal-actions {
        display: flex;
        justify-content: flex-end;
        gap: 0.5rem;
        margin-top: 1.5rem;
    }

    .cancel-btn, .save-btn {
        padding: 0.5rem 1rem;
        border: none;
        border-radius: 0.5rem;
        cursor: pointer;
    }

    .cancel-btn {
        background: #2a2a3e;
        color: #fff;
    }

    .save-btn {
        background: #7c3aed;
        color: #fff;
    }

    .save-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
</style>
