<script lang="ts">
    import { onMount } from 'svelte';
    import { authApi } from '$lib/api';
    import { goto } from '$app/navigation';
    import { isAuthenticated, auth } from '$lib/stores/auth';

    let totpEnabled = false;
    let totpVerified = false;
    let loading = true;
    let error = '';

    // Setup state
    let setupMode = false;
    let qrCode = '';
    let secret = '';
    let backupCodes: string[] = [];
    let verifyCode = '';
    let verifying = false;

    // Disable state
    let disableMode = false;
    let disableCode = '';
    let disabling = false;

    // API Keys
    let apiKeys: { id: string; name: string; created_at: string; last_used?: string }[] = [];
    let newKeyName = '';
    let creatingKey = false;
    let newKey: { key: string; name: string } | null = null;

    onMount(async () => {
        if (!$isAuthenticated) {
            goto('/login');
            return;
        }

        try {
            const [status, keys] = await Promise.all([
                authApi.totpStatus(),
                authApi.listApiKeys(),
            ]);
            totpEnabled = status.enabled;
            totpVerified = status.verified;
            apiKeys = keys;
        } catch (e: any) {
            error = e.message;
        } finally {
            loading = false;
        }
    });

    async function startTotpSetup() {
        error = '';
        try {
            const result = await authApi.enableTotp();
            qrCode = result.qr_code;
            secret = result.secret;
            backupCodes = result.backup_codes;
            setupMode = true;
        } catch (e: any) {
            error = e.message;
        }
    }

    async function verifySetup() {
        error = '';
        verifying = true;
        try {
            await authApi.verifyTotp(verifyCode);
            totpEnabled = true;
            totpVerified = true;
            setupMode = false;
            qrCode = '';
            secret = '';
            verifyCode = '';
        } catch (e: any) {
            error = e.message;
        } finally {
            verifying = false;
        }
    }

    async function disableTotp() {
        error = '';
        disabling = true;
        try {
            await authApi.disableTotp(disableCode);
            totpEnabled = false;
            totpVerified = false;
            disableMode = false;
            disableCode = '';
            backupCodes = [];
        } catch (e: any) {
            error = e.message;
        } finally {
            disabling = false;
        }
    }

    async function createApiKey() {
        if (!newKeyName.trim()) return;
        error = '';
        creatingKey = true;
        try {
            const result = await authApi.createApiKey(newKeyName);
            newKey = { key: result.key, name: result.name };
            apiKeys = [...apiKeys, {
                id: result.id,
                name: result.name,
                created_at: result.created_at,
            }];
            newKeyName = '';
        } catch (e: any) {
            error = e.message;
        } finally {
            creatingKey = false;
        }
    }

    async function revokeKey(id: string) {
        try {
            await authApi.revokeApiKey(id);
            apiKeys = apiKeys.filter(k => k.id !== id);
        } catch (e: any) {
            error = e.message;
        }
    }

    function copyToClipboard(text: string) {
        navigator.clipboard.writeText(text);
    }
</script>

<svelte:head>
    <title>Settings - Burrow</title>
</svelte:head>

<div class="settings-page">
    <h1>Settings</h1>

    {#if error}
        <div class="error">{error}</div>
    {/if}

    {#if loading}
        <div class="loading">Loading...</div>
    {:else}
        <!-- 2FA Section -->
        <section class="card">
            <h2>Two-Factor Authentication</h2>
            <p class="description">
                Add an extra layer of security to your account using an authenticator app.
            </p>

            {#if setupMode}
                <div class="setup-container">
                    <div class="qr-section">
                        <h3>1. Scan QR Code</h3>
                        <p>Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)</p>
                        <div class="qr-code">
                            <img src="data:image/png;base64,{qrCode}" alt="QR Code" />
                        </div>
                        <p class="manual-entry">
                            Or enter manually: <code>{secret}</code>
                            <button class="copy-btn" on:click={() => copyToClipboard(secret)}>Copy</button>
                        </p>
                    </div>

                    <div class="backup-section">
                        <h3>2. Save Backup Codes</h3>
                        <p>Store these codes safely. You can use them to access your account if you lose your device.</p>
                        <div class="backup-codes">
                            {#each backupCodes as code}
                                <code>{code}</code>
                            {/each}
                        </div>
                        <button class="copy-btn" on:click={() => copyToClipboard(backupCodes.join('\n'))}>
                            Copy All Codes
                        </button>
                    </div>

                    <div class="verify-section">
                        <h3>3. Verify Setup</h3>
                        <p>Enter the 6-digit code from your authenticator app to complete setup.</p>
                        <form on:submit|preventDefault={verifySetup}>
                            <input
                                type="text"
                                bind:value={verifyCode}
                                placeholder="000000"
                                maxlength="6"
                                pattern="[0-9]{6}"
                                required
                            />
                            <button type="submit" disabled={verifying || verifyCode.length !== 6}>
                                {verifying ? 'Verifying...' : 'Verify & Enable'}
                            </button>
                        </form>
                    </div>

                    <button class="cancel-btn" on:click={() => { setupMode = false; qrCode = ''; }}>
                        Cancel Setup
                    </button>
                </div>
            {:else if disableMode}
                <div class="disable-container">
                    <h3>Disable Two-Factor Authentication</h3>
                    <p>Enter your current 2FA code to disable two-factor authentication.</p>
                    <form on:submit|preventDefault={disableTotp}>
                        <input
                            type="text"
                            bind:value={disableCode}
                            placeholder="000000"
                            maxlength="6"
                            pattern="[0-9]{6}"
                            required
                        />
                        <div class="button-group">
                            <button type="submit" class="danger" disabled={disabling || disableCode.length !== 6}>
                                {disabling ? 'Disabling...' : 'Disable 2FA'}
                            </button>
                            <button type="button" class="cancel-btn" on:click={() => { disableMode = false; disableCode = ''; }}>
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>
            {:else}
                <div class="status">
                    <span class="status-badge" class:enabled={totpEnabled}>
                        {totpEnabled ? 'Enabled' : 'Disabled'}
                    </span>
                </div>
                {#if totpEnabled}
                    <button class="danger" on:click={() => disableMode = true}>
                        Disable 2FA
                    </button>
                {:else}
                    <button class="primary" on:click={startTotpSetup}>
                        Enable 2FA
                    </button>
                {/if}
            {/if}
        </section>

        <!-- API Keys Section -->
        <section class="card">
            <h2>API Keys</h2>
            <p class="description">
                Generate API keys to use with the Burrow CLI or for programmatic access.
            </p>

            {#if newKey}
                <div class="new-key-alert">
                    <h4>New API Key Created</h4>
                    <p>Copy this key now. You won't be able to see it again!</p>
                    <div class="key-display">
                        <code>{newKey.key}</code>
                        <button class="copy-btn" on:click={() => copyToClipboard(newKey?.key || '')}>Copy</button>
                    </div>
                    <button on:click={() => newKey = null}>Done</button>
                </div>
            {/if}

            <form class="create-key-form" on:submit|preventDefault={createApiKey}>
                <input
                    type="text"
                    bind:value={newKeyName}
                    placeholder="Key name (e.g., CLI, CI/CD)"
                    required
                />
                <button type="submit" disabled={creatingKey || !newKeyName.trim()}>
                    {creatingKey ? 'Creating...' : 'Create Key'}
                </button>
            </form>

            {#if apiKeys.length > 0}
                <div class="keys-list">
                    {#each apiKeys as key}
                        <div class="key-item">
                            <div class="key-info">
                                <strong>{key.name}</strong>
                                <span class="key-meta">
                                    Created: {new Date(key.created_at).toLocaleDateString()}
                                    {#if key.last_used}
                                        | Last used: {new Date(key.last_used).toLocaleDateString()}
                                    {/if}
                                </span>
                            </div>
                            <button class="danger-sm" on:click={() => revokeKey(key.id)}>Revoke</button>
                        </div>
                    {/each}
                </div>
            {:else}
                <p class="no-keys">No API keys created yet.</p>
            {/if}
        </section>

        <!-- Account Info -->
        <section class="card">
            <h2>Account</h2>
            {#if $auth.user}
                <div class="account-info">
                    <p><strong>Name:</strong> {$auth.user.name}</p>
                    <p><strong>Email:</strong> {$auth.user.email}</p>
                    <p><strong>Role:</strong> <span class="role-badge">{$auth.user.role}</span></p>
                </div>
            {/if}
        </section>
    {/if}
</div>

<style>
    .settings-page {
        max-width: 800px;
        margin: 0 auto;
    }

    h1 {
        color: #fff;
        margin-bottom: 2rem;
    }

    .card {
        background: #1a1a2e;
        border-radius: 1rem;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
    }

    .card h2 {
        color: #fff;
        margin-top: 0;
        margin-bottom: 0.5rem;
        font-size: 1.25rem;
    }

    .description {
        color: #888;
        margin-bottom: 1.5rem;
    }

    .error {
        background: #ff4444;
        color: #fff;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }

    .loading {
        color: #888;
        text-align: center;
        padding: 2rem;
    }

    /* 2FA Styles */
    .status {
        margin-bottom: 1rem;
    }

    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 1rem;
        font-size: 0.875rem;
        background: #4a4a5a;
        color: #888;
    }

    .status-badge.enabled {
        background: #10b981;
        color: #fff;
    }

    .setup-container, .disable-container {
        background: #0f0f1a;
        border-radius: 0.5rem;
        padding: 1.5rem;
    }

    .setup-container h3, .disable-container h3 {
        color: #fff;
        margin-top: 0;
    }

    .qr-code {
        background: #fff;
        padding: 1rem;
        border-radius: 0.5rem;
        display: inline-block;
        margin: 1rem 0;
    }

    .qr-code img {
        width: 200px;
        height: 200px;
    }

    .manual-entry {
        font-size: 0.875rem;
        color: #888;
    }

    .manual-entry code {
        background: #2a2a3e;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-family: monospace;
        word-break: break-all;
    }

    .backup-codes {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 0.5rem;
        margin: 1rem 0;
    }

    .backup-codes code {
        background: #2a2a3e;
        padding: 0.5rem;
        border-radius: 0.25rem;
        font-family: monospace;
        text-align: center;
    }

    .backup-section, .verify-section {
        margin-top: 2rem;
        padding-top: 1.5rem;
        border-top: 1px solid #2a2a3e;
    }

    form {
        display: flex;
        gap: 1rem;
        flex-wrap: wrap;
    }

    input[type="text"] {
        flex: 1;
        min-width: 200px;
        padding: 0.75rem;
        border: 1px solid #4a4a5a;
        border-radius: 0.5rem;
        background: #0f0f1a;
        color: #fff;
        font-size: 1rem;
    }

    input:focus {
        outline: none;
        border-color: #7c3aed;
    }

    button {
        padding: 0.75rem 1.5rem;
        border: none;
        border-radius: 0.5rem;
        cursor: pointer;
        font-size: 1rem;
        transition: all 0.2s;
    }

    button.primary {
        background: #7c3aed;
        color: #fff;
    }

    button.primary:hover {
        background: #6d28d9;
    }

    button.danger {
        background: #dc2626;
        color: #fff;
    }

    button.danger:hover {
        background: #b91c1c;
    }

    button.danger-sm {
        background: transparent;
        border: 1px solid #dc2626;
        color: #dc2626;
        padding: 0.5rem 1rem;
        font-size: 0.875rem;
    }

    button.danger-sm:hover {
        background: #dc2626;
        color: #fff;
    }

    button.cancel-btn {
        background: #4a4a5a;
        color: #fff;
    }

    button.copy-btn {
        background: #4a4a5a;
        color: #fff;
        padding: 0.25rem 0.75rem;
        font-size: 0.75rem;
    }

    button:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }

    .button-group {
        display: flex;
        gap: 1rem;
    }

    /* API Keys Styles */
    .new-key-alert {
        background: #10b981;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }

    .new-key-alert h4 {
        margin: 0 0 0.5rem 0;
        color: #fff;
    }

    .new-key-alert p {
        margin: 0 0 1rem 0;
        color: rgba(255, 255, 255, 0.9);
    }

    .key-display {
        display: flex;
        gap: 0.5rem;
        align-items: center;
        margin-bottom: 1rem;
    }

    .key-display code {
        flex: 1;
        background: rgba(0, 0, 0, 0.2);
        padding: 0.5rem;
        border-radius: 0.25rem;
        font-family: monospace;
        word-break: break-all;
    }

    .create-key-form {
        margin-bottom: 1.5rem;
    }

    .keys-list {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
    }

    .key-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: #0f0f1a;
        padding: 1rem;
        border-radius: 0.5rem;
    }

    .key-info strong {
        display: block;
        color: #fff;
    }

    .key-meta {
        font-size: 0.75rem;
        color: #888;
    }

    .no-keys {
        color: #888;
        font-style: italic;
    }

    /* Account Styles */
    .account-info p {
        color: #ddd;
        margin: 0.5rem 0;
    }

    .role-badge {
        display: inline-block;
        padding: 0.125rem 0.5rem;
        border-radius: 0.25rem;
        background: #7c3aed;
        color: #fff;
        font-size: 0.75rem;
        text-transform: uppercase;
    }
</style>
