<script lang="ts">
    import { goto } from '$app/navigation';
    import { authApi } from '$lib/api';
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
        } catch (e: any) {
            error = e.message || 'Registration failed';
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
    .auth-page {
        min-height: 80vh;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .auth-card {
        background: #16213e;
        padding: 2.5rem;
        border-radius: 1rem;
        width: 100%;
        max-width: 400px;
    }

    h1 {
        margin: 0 0 0.5rem;
        font-size: 1.75rem;
    }

    .subtitle {
        color: #a0a0a0;
        margin: 0 0 2rem;
    }

    .error {
        background: rgba(239, 68, 68, 0.2);
        border: 1px solid rgba(239, 68, 68, 0.5);
        color: #f87171;
        padding: 0.75rem 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1.5rem;
    }

    form {
        display: flex;
        flex-direction: column;
        gap: 1.25rem;
    }

    .field {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }

    label {
        font-size: 0.875rem;
        color: #a0a0a0;
    }

    input {
        background: #0f0f1a;
        border: 1px solid #2d2d44;
        border-radius: 0.5rem;
        padding: 0.75rem 1rem;
        color: #fff;
        font-size: 1rem;
    }

    input:focus {
        outline: none;
        border-color: #7c3aed;
    }

    input::placeholder {
        color: #4a4a5a;
    }

    button {
        background: #7c3aed;
        color: white;
        border: none;
        border-radius: 0.5rem;
        padding: 0.875rem 1.5rem;
        font-size: 1rem;
        font-weight: 500;
        cursor: pointer;
        margin-top: 0.5rem;
    }

    button:hover:not(:disabled) {
        background: #6d28d9;
    }

    button:disabled {
        opacity: 0.6;
        cursor: not-allowed;
    }

    .footer {
        text-align: center;
        margin: 1.5rem 0 0;
        color: #a0a0a0;
    }

    .footer a {
        color: #7c3aed;
        text-decoration: none;
    }

    .footer a:hover {
        text-decoration: underline;
    }
</style>
