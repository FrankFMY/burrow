<script lang="ts">
import { onMount } from 'svelte';
import { page } from '$app/stores';
import { goto } from '$app/navigation';
import { getErrorMessage } from '$lib/api';

let token = '';
let newPassword = '';
let confirmPassword = '';
let error = '';
let success = false;
let loading = false;
let validToken = true;

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

onMount(() => {
    token = $page.url.searchParams.get('token') || '';
    if (!token) {
        validToken = false;
    }
});

async function handleSubmit() {
    error = '';

    if (newPassword !== confirmPassword) {
        error = 'Passwords do not match';
        return;
    }

    if (newPassword.length < 8) {
        error = 'Password must be at least 8 characters';
        return;
    }

    loading = true;

    try {
        const response = await fetch(`${API_URL}/api/auth/reset-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                token,
                new_password: newPassword,
            }),
        });

        const data = await response.json();

        if (response.ok) {
            success = true;
        } else {
            error = data.error || 'Failed to reset password. Please try again.';
        }
    } catch (e: unknown) {
        error = getErrorMessage(e);
    } finally {
        loading = false;
    }
}

function goToLogin() {
    goto('/login');
}
</script>

<svelte:head><title>Reset Password - Burrow</title></svelte:head>

<div class="auth-page">
    <div class="auth-card">
        {#if !validToken}
            <div class="error-state">
                <div class="icon error-icon">!</div>
                <h1>Invalid Link</h1>
                <p>This password reset link is invalid or missing.</p>
                <a href="/forgot-password" class="button">Request New Link</a>
            </div>
        {:else if success}
            <div class="success-state">
                <div class="icon success-icon">&#10004;</div>
                <h1>Password Reset!</h1>
                <p>Your password has been successfully changed.</p>
                <p class="secondary">You can now log in with your new password.</p>
                <button on:click={goToLogin} class="button">Go to Login</button>
            </div>
        {:else}
            <h1>Reset Password</h1>
            <p class="subtitle">Enter your new password</p>

            {#if error}
                <div class="error">{error}</div>
            {/if}

            <form on:submit|preventDefault={handleSubmit}>
                <div class="field">
                    <label for="newPassword">New Password</label>
                    <input
                        id="newPassword"
                        type="password"
                        bind:value={newPassword}
                        required
                        placeholder="Enter new password"
                        minlength="8"
                        autocomplete="new-password"
                    />
                </div>

                <div class="field">
                    <label for="confirmPassword">Confirm Password</label>
                    <input
                        id="confirmPassword"
                        type="password"
                        bind:value={confirmPassword}
                        required
                        placeholder="Confirm new password"
                        minlength="8"
                        autocomplete="new-password"
                    />
                </div>

                <small class="hint">
                    Password must be at least 8 characters and contain both letters and numbers.
                </small>

                <button type="submit" disabled={loading}>
                    {loading ? 'Resetting...' : 'Reset Password'}
                </button>
            </form>

            <p class="footer">
                Remember your password? <a href="/login">Login</a>
            </p>
        {/if}
    </div>
</div>

<style>
    .success-state, .error-state {
        text-align: center;
    }

    .icon {
        width: 60px;
        height: 60px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 24px;
        font-weight: bold;
        margin: 0 auto 1rem;
    }

    .success-icon {
        background: rgba(34, 197, 94, 0.2);
        color: #22c55e;
    }

    .error-icon {
        background: rgba(239, 68, 68, 0.2);
        color: #ef4444;
    }

    .secondary {
        font-size: 0.875rem;
        color: #6b6b7b;
        margin-top: 1rem;
    }

    .hint {
        display: block;
        color: #6b6b7b;
        font-size: 0.75rem;
        margin-bottom: 1rem;
    }

    .button {
        display: inline-block;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 8px;
        cursor: pointer;
        font-size: 1rem;
        margin-top: 1.5rem;
        text-decoration: none;
        transition: opacity 0.2s;
    }

    .button:hover {
        opacity: 0.9;
    }
</style>
