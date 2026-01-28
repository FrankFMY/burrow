<script lang="ts">
import { notifications, type NotificationType } from '$lib/stores/notifications';

export let id: string;
export let type: NotificationType;
export let message: string;

function dismiss() {
    notifications.remove(id);
}

const icons: Record<NotificationType, string> = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ',
};
</script>

<div class="toast toast-{type}" role="alert">
    <div class="toast-icon">{icons[type]}</div>
    <div class="toast-message">{message}</div>
    <button class="toast-close" on:click={dismiss} aria-label="Dismiss">×</button>
</div>

<style>
    .toast {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 1rem 1.25rem;
        border-radius: 0.5rem;
        background: #1a1a2e;
        border: 1px solid #2a2a3e;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        animation: slideIn 0.3s ease-out;
        min-width: 300px;
        max-width: 450px;
    }

    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    .toast-icon {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 1.5rem;
        height: 1.5rem;
        border-radius: 50%;
        font-size: 0.875rem;
        font-weight: bold;
        flex-shrink: 0;
    }

    .toast-success .toast-icon {
        background: rgba(74, 222, 128, 0.2);
        color: #4ade80;
    }

    .toast-error .toast-icon {
        background: rgba(248, 113, 113, 0.2);
        color: #f87171;
    }

    .toast-warning .toast-icon {
        background: rgba(250, 204, 21, 0.2);
        color: #facc15;
    }

    .toast-info .toast-icon {
        background: rgba(96, 165, 250, 0.2);
        color: #60a5fa;
    }

    .toast-message {
        flex: 1;
        color: #fff;
        font-size: 0.875rem;
        line-height: 1.4;
    }

    .toast-close {
        background: none;
        border: none;
        color: #6a6a7a;
        cursor: pointer;
        font-size: 1.25rem;
        padding: 0;
        line-height: 1;
        transition: color 0.2s;
    }

    .toast-close:hover {
        color: #fff;
    }
</style>
