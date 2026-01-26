<script lang="ts">
import { goto } from '$app/navigation';
import { authApi, getErrorMessage } from '$lib/api';
import { auth } from '$lib/stores/auth';

let name = '';
let email = '';
let password = '';
let confirmPassword = '';
let error = '';
let loading = false;

async function handleSubmit() {
    error = '';

    if (password !== confirmPassword) {
        error = 'Passwords do not match';
        return;
    }

    if (password.length < 8) {
        error = 'Password must be at least 8 characters';
        return;
    }

    loading = true;

    try {
        const result = await authApi.register({ name, email, password });
        auth.setAuth(result.token, result.user);
        goto('/');
    } catch (e: unknown) {
        error = getErrorMessage(e);
    } finally {
        loading = false;
    }
}
</script>

<svelte:head><title>Register - Burrow</title></svelte:head>

<div class="auth-page">
    <div class="auth-card">
        <h1>Create Account</h1>
        <p class="subtitle">Join Burrow to create mesh networks</p>

        {#if error}
            <div class="error">{error}</div>
        {/if}

        <form on:submit|preventDefault={handleSubmit}>
            <div class="field">
                <label for="name">Name</label>
                <input
                    id="name"
                    type="text"
                    bind:value={name}
                    required
                    placeholder="Your name"
                />
            </div>

            <div class="field">
                <label for="email">Email</label>
                <input
                    id="email"
                    type="email"
                    bind:value={email}
                    required
                    placeholder="you@example.com"
                />
            </div>

            <div class="field">
                <label for="password">Password</label>
                <input
                    id="password"
                    type="password"
                    bind:value={password}
                    required
                    placeholder="At least 8 characters"
                />
            </div>

            <div class="field">
                <label for="confirmPassword">Confirm Password</label>
                <input
                    id="confirmPassword"
                    type="password"
                    bind:value={confirmPassword}
                    required
                    placeholder="Confirm your password"
                />
            </div>

            <button type="submit" disabled={loading}>
                {loading ? 'Creating account...' : 'Create Account'}
            </button>
        </form>

        <p class="footer">
            Already have an account? <a href="/login">Sign in</a>
        </p>
    </div>
</div>

<style>
    /* Auth page styles are in app.css */
</style>
