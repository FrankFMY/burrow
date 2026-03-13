import {
	getStatus,
	getServers,
	getPreferences,
	setPreferences,
	waitForDaemon,
	type TunnelStatus,
	type Server,
	type Preferences
} from './api';
import { t } from './i18n.svelte';

let _status = $state<TunnelStatus | null>(null);
let _servers = $state<Server[]>([]);
let _preferences = $state<Preferences>({ tun_mode: true, kill_switch: false, auto_connect: false });
let _daemonReady = $state(false);
let _loading = $state(false);
let _error = $state('');
let _speedUp = $state(0);
let _speedDown = $state(0);
let _prefSaved = $state(false);
let _prefSavedTimer: ReturnType<typeof setTimeout> | null = null;

let _prevBytesUp = 0;
let _prevBytesDown = 0;
let _prevTimestamp = 0;
let _pollInterval: ReturnType<typeof setInterval> | null = null;
let _pollFailures = 0;
let _initialized = false;
let _initPromise: Promise<void> | null = null;

export const store = {
	get status() {
		return _status;
	},
	set status(v: TunnelStatus | null) {
		_status = v;
	},

	get servers() {
		return _servers;
	},
	set servers(v: Server[]) {
		_servers = v;
	},

	get preferences() {
		return _preferences;
	},

	get daemonReady() {
		return _daemonReady;
	},
	set daemonReady(v: boolean) {
		_daemonReady = v;
	},

	get loading() {
		return _loading;
	},
	set loading(v: boolean) {
		_loading = v;
	},

	get error() {
		return _error;
	},
	set error(v: string) {
		_error = v;
	},

	get connected() {
		return _status?.running ?? false;
	},

	get speedUp() {
		return _speedUp;
	},

	get speedDown() {
		return _speedDown;
	},

	get prefSaved() {
		return _prefSaved;
	},

	get initialized() {
		return _initialized;
	},

	async refreshStatus() {
		try {
			const [s, srv] = await Promise.all([
				getStatus(),
				getServers()
			]);
			_pollFailures = 0;
			_status = s;
			_servers = srv;

			if (s && s.running) {
				_error = '';
				const now = Date.now();
				if (_prevTimestamp > 0) {
					const dt = (now - _prevTimestamp) / 1000;
					if (dt > 0) {
						_speedUp = Math.max(0, (s.bytes_up - _prevBytesUp) / dt);
						_speedDown = Math.max(0, (s.bytes_down - _prevBytesDown) / dt);
					}
				}
				_prevBytesUp = s.bytes_up;
				_prevBytesDown = s.bytes_down;
				_prevTimestamp = now;
			} else {
				_speedUp = 0;
				_speedDown = 0;
				_prevBytesUp = 0;
				_prevBytesDown = 0;
				_prevTimestamp = 0;
			}
		} catch {
			_pollFailures++;
			if (_pollFailures >= 3) {
				_error = t('status.daemon_error');
				_status = null;
			}
		}
	},

	async refreshPreferences() {
		try {
			const prefs = await getPreferences();
			_preferences = prefs;
		} catch {
			if (_daemonReady) {
				_error = t('status.daemon_error');
			}
		}
	},

	async updatePreference(partial: Partial<Preferences>) {
		const prev = { ..._preferences };
		_preferences = { ..._preferences, ...partial };
		try {
			const updated = await setPreferences(partial);
			_preferences = updated;
			if (_prefSavedTimer) clearTimeout(_prefSavedTimer);
			_prefSaved = true;
			_prefSavedTimer = setTimeout(() => { _prefSaved = false; }, 1500);
		} catch {
			_preferences = prev;
			await this.refreshPreferences();
		}
	},

	async init() {
		if (_initPromise) return _initPromise;
		_initPromise = this._doInit();
		return _initPromise;
	},

	async _doInit() {
		if (_initialized) return;
		_initialized = true;

		_daemonReady = await waitForDaemon();
		if (!_initialized) return;
		if (!_daemonReady) {
			_error = t('status.daemon_error');
			return;
		}

		await Promise.all([this.refreshStatus(), this.refreshPreferences()]);
		if (!_initialized) return;

		_pollInterval = setInterval(() => {
			this.refreshStatus();
		}, 2000);
	},

	destroy() {
		if (_pollInterval) {
			clearInterval(_pollInterval);
			_pollInterval = null;
		}
		if (_prefSavedTimer) {
			clearTimeout(_prefSavedTimer);
			_prefSavedTimer = null;
		}
		_pollFailures = 0;
		_initialized = false;
		_initPromise = null;
	}
};
