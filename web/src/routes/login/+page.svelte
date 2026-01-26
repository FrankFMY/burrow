<script lang="ts">
import { goto } from '$app/navigation';
import { authApi, getErrorMessage } from '$lib/api';
import { auth } from '$lib/stores/auth';

let email = '';
let password = '';
let totpCode = '';
let error = '';
let loading = false;
let requires2FA = false;

async function handleSubmit() {
    error = '';
    loading = true;

    try {
        const loginData: { email: string; password: string; totp_code?: string } = {
            email,
            password,
        };

        if (requires2FA && totpCode) {
            loginData.totp_code = totpCode;
        }

        const result = await authApi.login(loginData);
        auth.setAuth(result.token, result.user);
        goto('/');
    } catch (e: unknown) {
        const errorMsg = getErrorMessage(e);

        // Check if 2FA is required
        if (errorMsg.includes('2FA') || errorMsg.includes('code required')) {
            requires2FA = true;
            error = 'Please enter your 2FA code';
        } else {
            error = errorMsg;
        }
    } finally {
        loading = false;
    }
}
</script>

<svelte:head><title>Login - Burrow</title></svelte:head>

<div class="auth-page">
    <div class="auth-card">
        <h1>Login</h1>
        <p class="subtitle">Sign in to your Burrow account</p>

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
                    disabled={requires2FA}
                />
            </div>

            <div class="field">
                <label for="password">Password</label>
                <input
                    id="password"
                    type="password"
                    bind:value={password}
                    required
                    placeholder="Your password"
                    disabled={requires2FA}
                />
            </div>

            {#if requires2FA}
                <div class="field">
                    <label for="totp">2FA Code</label>
                    <input
                        id="totp"
                        type="text"
                        bind:value={totpCode}
                        required
                        placeholder="Enter 6-digit code"
                        maxlength="6"
                        pattern="[0-9]{6}"
                        autocomplete="one-time-code"
                    />
                    <small class="hint">Enter the code from your authenticator app</small>
                </div>
            {/if}

            <button type="submit" disabled={loading}>
                {loading ? 'Signing in...' : (requires2FA ? 'Verify & Sign In' : 'Sign In')}
            </button>

            {#if requires2FA}
                <button
                    type="button"
                    class="secondary"
                    on:click={() => { requires2FA = false; totpCode = ''; error = ''; }}
                >
                    Back
                </button>
            {/if}
        </form>

        <p class="footer">
            Don't have an account? <a href="/register">Register</a>
        </p>
    </div>
</div>

<style>
    /* Auth page styles are in app.css */
    .hint {
        color: #6b6b7b;
        font-size: 0.75rem;
    }
    button.secondary {
        background: transparent;
        border: 1px solid #2d2d44;
        color: #a0a0a0;
        margin-top: 0;
    }
    button.secondary:hover {
        background: rgba(255, 255, 255, 0.05);
    }
</style>
