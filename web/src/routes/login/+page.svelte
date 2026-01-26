<script lang="ts">
    import { goto } from '$app/navigation';
    import { authApi } from '$lib/api';
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
        } catch (e: any) {
            const errorMsg = e.message || 'Login failed';

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

    input:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }

    .hint {
        color: #6b6b7b;
        font-size: 0.75rem;
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

    button.secondary {
        background: transparent;
        border: 1px solid #2d2d44;
        color: #a0a0a0;
        margin-top: 0;
    }

    button.secondary:hover {
        background: rgba(255, 255, 255, 0.05);
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
