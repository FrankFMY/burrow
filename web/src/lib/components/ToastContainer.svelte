<script lang="ts">
import { notifications } from '$lib/stores/notifications';
import Toast from './Toast.svelte';
</script>

{#if $notifications.length > 0}
<div class="toast-container" aria-live="polite">
    {#each $notifications as notification (notification.id)}
        <Toast
            id={notification.id}
            type={notification.type}
            message={notification.message}
        />
    {/each}
</div>
{/if}

<style>
    .toast-container {
        position: fixed;
        top: 5rem;
        right: 1rem;
        z-index: 9999;
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
        pointer-events: none;
    }

    .toast-container > :global(*) {
        pointer-events: auto;
    }

    @media (max-width: 768px) {
        .toast-container {
            top: auto;
            bottom: 1rem;
            right: 0.5rem;
            left: 0.5rem;
        }
    }
</style>
