import { derived, get, writable } from 'svelte/store';
import { browser } from '$app/environment';
import { auth } from './auth';

export interface WsEvent {
    type:
        | 'NodeStatus'
        | 'NodeJoined'
        | 'NodeLeft'
        | 'NetworkCreated'
        | 'NetworkDeleted'
        | 'Ping'
        | 'Pong'
        | 'Error';
    data?: {
        network_id?: string;
        node_id?: string;
        name?: string;
        status?: string;
        mesh_ip?: string;
        endpoint?: string;
        message?: string;
    };
}

interface WsState {
    connected: boolean;
    events: WsEvent[];
    lastEvent: WsEvent | null;
}

function createWebSocketStore() {
    const { subscribe, set, update } = writable<WsState>({
        connected: false,
        events: [],
        lastEvent: null,
    });

    let ws: WebSocket | null = null;
    let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
    let pingInterval: ReturnType<typeof setInterval> | null = null;

    function connect(networkId?: string) {
        if (!browser) return;
        if (ws?.readyState === WebSocket.OPEN) return;

        // Get authentication token
        const { token } = get(auth);
        if (!token) {
            console.warn('WebSocket connection requires authentication');
            return;
        }

        const protocol = globalThis.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = import.meta.env.VITE_API_URL
            ? new URL(import.meta.env.VITE_API_URL).host
            : globalThis.location.host;

        // Build URL with token and optional network_id
        const params = new URLSearchParams();
        params.set('token', token);
        if (networkId) {
            params.set('network_id', networkId);
        }
        const url = `${protocol}//${host}/ws?${params.toString()}`;

        ws = new WebSocket(url);

        ws.onopen = () => {
            console.log('WebSocket connected');
            update((s) => ({ ...s, connected: true }));

            // Start ping interval
            pingInterval = setInterval(() => {
                if (ws?.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'Ping' }));
                }
            }, 30000);
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data) as WsEvent;
                update((s) => ({
                    ...s,
                    events: [...s.events.slice(-99), data], // Keep last 100 events
                    lastEvent: data,
                }));
            } catch (e) {
                console.error('Failed to parse WebSocket message:', e);
            }
        };

        ws.onclose = () => {
            console.log('WebSocket disconnected');
            update((s) => ({ ...s, connected: false }));
            cleanup();

            // Reconnect after 5 seconds
            reconnectTimeout = setTimeout(() => connect(networkId), 5000);
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    function disconnect() {
        cleanup();
        if (ws) {
            ws.close();
            ws = null;
        }
        set({ connected: false, events: [], lastEvent: null });
    }

    function cleanup() {
        if (reconnectTimeout) {
            clearTimeout(reconnectTimeout);
            reconnectTimeout = null;
        }
        if (pingInterval) {
            clearInterval(pingInterval);
            pingInterval = null;
        }
    }

    function send(event: WsEvent) {
        if (ws?.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(event));
        }
    }

    return {
        subscribe,
        connect,
        disconnect,
        send,
    };
}

export const websocket = createWebSocketStore();

// Derived stores for specific event types
export const nodeEvents = derived(websocket, ($ws) =>
    $ws.events.filter(
        (e) => e.type === 'NodeStatus' || e.type === 'NodeJoined' || e.type === 'NodeLeft'
    )
);

export const isWsConnected = derived(websocket, ($ws) => $ws.connected);
