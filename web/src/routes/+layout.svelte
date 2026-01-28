<script lang="ts">
import '../app.css';
import { onMount } from 'svelte';
import { goto } from '$app/navigation';
import { authApi } from '$lib/api';
import { auth, isAuthenticated } from '$lib/stores/auth';
import ToastContainer from '$lib/components/ToastContainer.svelte';

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
                {#if $auth.user?.role === 'admin'}
                    <a href="/admin" class="admin-link">Admin</a>
                {/if}
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

<ToastContainer />

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
    nav a.admin-link { color: #7c3aed; }
    nav a.admin-link:hover { color: #a78bfa; }
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

    /* Mobile responsive */
    @media (max-width: 768px) {
        header {
            padding: 0.75rem 1rem;
            flex-wrap: wrap;
        }

        .logo {
            font-size: 1.25rem;
        }

        nav {
            gap: 1rem;
            font-size: 0.875rem;
        }

        main {
            padding: 1rem;
        }
    }

    @media (max-width: 480px) {
        header {
            flex-direction: column;
            gap: 0.75rem;
        }

        nav {
            width: 100%;
            justify-content: center;
            flex-wrap: wrap;
        }

        .logout-btn {
            padding: 0.375rem 0.75rem;
            font-size: 0.75rem;
        }
    }
</style>
