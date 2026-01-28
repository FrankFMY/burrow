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
    let intentionalDisconnect = false; // Flag to prevent reconnection on intentional disconnect
    let currentNetworkId: string | undefined = undefined; // Track current network for reconnection

    function connect(networkId?: string) {
        if (!browser) return;
        // Check both OPEN and CONNECTING states to prevent duplicate connections
        if (ws?.readyState === WebSocket.OPEN || ws?.readyState === WebSocket.CONNECTING) return;

        intentionalDisconnect = false;
        currentNetworkId = networkId;

        // Check if user is authenticated (token exists in store means logged in)
        const { token } = get(auth);
        if (!token) {
            console.warn('WebSocket connection requires authentication');
            return;
        }

        const protocol = globalThis.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = import.meta.env.VITE_API_URL
            ? new URL(import.meta.env.VITE_API_URL).host
            : globalThis.location.host;

        // Build URL with only network_id filter (auth via httpOnly cookie or initial message)
        // Token is NOT passed in URL to avoid logging/exposure
        const params = new URLSearchParams();
        if (networkId) {
            params.set('network_id', networkId);
        }
        const baseUrl = `${protocol}//${host}/ws`;
        const url = params.toString() ? `${baseUrl}?${params.toString()}` : baseUrl;

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

            // Only reconnect if disconnect was not intentional
            if (!intentionalDisconnect) {
                reconnectTimeout = setTimeout(() => connect(currentNetworkId), 5000);
            }
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    function disconnect() {
        intentionalDisconnect = true; // Prevent reconnection in onclose handler
        cleanup();
        if (ws) {
            ws.close();
            ws = null;
        }
        currentNetworkId = undefined;
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
