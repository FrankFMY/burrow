<script lang="ts">
import { getErrorMessage } from '$lib/api';

let email = '';
let error = '';
let success = false;
let loading = false;

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

async function handleSubmit() {
    error = '';
    loading = true;

    try {
        const response = await fetch(`${API_URL}/api/auth/forgot-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email }),
        });

        const data = await response.json();

        if (response.ok) {
            success = true;
        } else {
            error = data.error || 'Failed to send reset email. Please try again.';
        }
    } catch (e: unknown) {
        error = getErrorMessage(e);
    } finally {
        loading = false;
    }
}
</script>

<svelte:head><title>Forgot Password - Burrow</title></svelte:head>

<div class="auth-page">
    <div class="auth-card">
        {#if success}
            <div class="success-state">
                <div class="icon success-icon">&#10004;</div>
                <h1>Check Your Email</h1>
                <p>If an account exists with that email, we've sent a password reset link.</p>
                <p class="secondary">The link will expire in 1 hour.</p>
                <a href="/login" class="button">Back to Login</a>
            </div>
        {:else}
            <h1>Forgot Password</h1>
            <p class="subtitle">Enter your email and we'll send you a reset link</p>

            {#if error}
                <div class="error">{error}</div>
            {/if}

            <form on:submit|preventDefault={handleSubmit}>
                <div class="field">
                    <label for="email">Email</label>
                    <input
                        id="email"
                        type="email"
                        bind:value={email}
                        required
                        placeholder="you@example.com"
                        autocomplete="email"
                    />
                </div>

                <button type="submit" disabled={loading}>
                    {loading ? 'Sending...' : 'Send Reset Link'}
                </button>
            </form>

            <p class="footer">
                Remember your password? <a href="/login">Login</a>
            </p>
        {/if}
    </div>
</div>

<style>
    .success-state {
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

    .secondary {
        font-size: 0.875rem;
        color: #6b6b7b;
        margin-top: 1rem;
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
