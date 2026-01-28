<script lang="ts">
import '../app.css';
import { onMount } from 'svelte';
import { goto } from '$app/navigation';
import { authApi } from '$lib/api';
import { auth, isAuthenticated } from '$lib/stores/auth';

onMount(async () => {
    // If we have a token but no user, fetch user info
    if ($auth.token && !$auth.user) {
        try {
            const user = await authApi.me();
            auth.setUser(user);
        } catch {
            // Token invalid, clear it
            auth.logout();
        }
    } else {
        auth.setLoading(false);
    }
});

async function handleLogout() {
    await auth.logoutAsync(); // Clears httpOnly cookie and localStorage
    goto('/login');
}
</script>

<div class="app">
    <header>
        <div class="logo">🕳️ <span>Burrow</span></div>
        <nav>
            {#if $isAuthenticated}
                <a href="/">Dashboard</a>
                <a href="/networks">Networks</a>
                <a href="/settings">Settings</a>
                <button class="logout-btn" on:click={handleLogout}>Logout</button>
            {:else}
                <a href="/login">Login</a>
                <a href="/register">Register</a>
            {/if}
        </nav>
    </header>
    <main><slot /></main>
</div>

<style>
    .app { min-height: 100vh; display: flex; flex-direction: column; }
    header {
        background: #1a1a2e;
        padding: 1rem 2rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .logo { font-size: 1.5rem; font-weight: bold; color: #fff; display: flex; gap: 0.5rem; }
    nav { display: flex; gap: 2rem; align-items: center; }
    nav a { color: #a0a0a0; text-decoration: none; }
    nav a:hover { color: #fff; }
    main { flex: 1; padding: 2rem; background: #0f0f1a; }
    .logout-btn {
        background: none;
        border: 1px solid #4a4a5a;
        color: #a0a0a0;
        padding: 0.5rem 1rem;
        border-radius: 0.5rem;
        cursor: pointer;
        font-size: 0.875rem;
    }
    .logout-btn:hover {
        border-color: #7c3aed;
        color: #fff;
    }
</style>
