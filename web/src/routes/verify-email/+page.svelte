<script lang="ts">
import { onMount } from 'svelte';
import { page } from '$app/stores';
import { goto } from '$app/navigation';
import { getErrorMessage } from '$lib/api';

let status: 'loading' | 'success' | 'error' = 'loading';
let message = '';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

onMount(async () => {
    const token = $page.url.searchParams.get('token');

    if (!token) {
        status = 'error';
        message = 'Invalid verification link. No token provided.';
        return;
    }

    try {
        const response = await fetch(`${API_URL}/api/auth/verify-email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token }),
        });

        const data = await response.json();

        if (response.ok) {
            status = 'success';
            message = data.message || 'Email verified successfully!';
        } else {
            status = 'error';
            message = data.error || 'Verification failed. Please try again.';
        }
    } catch (e: unknown) {
        status = 'error';
        message = getErrorMessage(e);
    }
});

function goToLogin() {
    goto('/login');
}

function goToHome() {
    goto('/');
}
</script>

<svelte:head><title>Verify Email - Burrow</title></svelte:head>

<div class="verify-page">
    <div class="verify-card">
        {#if status === 'loading'}
            <div class="loading">
                <div class="spinner"></div>
                <h2>Verifying your email...</h2>
                <p>Please wait while we confirm your email address.</p>
            </div>
        {:else if status === 'success'}
            <div class="success">
                <div class="icon success-icon">&#10004;</div>
                <h2>Email Verified!</h2>
                <p>{message}</p>
                <p class="secondary">You can now access all features of your Burrow account.</p>
                <button on:click={goToHome}>Continue to Dashboard</button>
            </div>
        {:else}
            <div class="error-state">
                <div class="icon error-icon">!</div>
                <h2>Verification Failed</h2>
                <p>{message}</p>
                <p class="secondary">The verification link may have expired or already been used.</p>
                <button on:click={goToLogin}>Go to Login</button>
            </div>
        {/if}
    </div>
</div>

<style>
    .verify-page {
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 2rem;
    }

    .verify-card {
        background: #1a1a2e;
        border: 1px solid #2d2d44;
        border-radius: 12px;
        padding: 3rem;
        max-width: 400px;
        width: 100%;
        text-align: center;
    }

    h2 {
        margin: 1rem 0 0.5rem;
        font-size: 1.5rem;
    }

    p {
        color: #a0a0a0;
        margin: 0.5rem 0;
    }

    p.secondary {
        font-size: 0.875rem;
        color: #6b6b7b;
        margin-top: 1rem;
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
        margin: 0 auto;
    }

    .success-icon {
        background: rgba(34, 197, 94, 0.2);
        color: #22c55e;
    }

    .error-icon {
        background: rgba(239, 68, 68, 0.2);
        color: #ef4444;
    }

    .loading {
        display: flex;
        flex-direction: column;
        align-items: center;
    }

    .spinner {
        width: 48px;
        height: 48px;
        border: 4px solid #2d2d44;
        border-top-color: #667eea;
        border-radius: 50%;
        animation: spin 1s linear infinite;
    }

    @keyframes spin {
        to {
            transform: rotate(360deg);
        }
    }

    button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 8px;
        cursor: pointer;
        font-size: 1rem;
        margin-top: 1.5rem;
        transition: opacity 0.2s;
    }

    button:hover {
        opacity: 0.9;
    }
</style>
