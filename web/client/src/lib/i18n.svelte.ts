type Locale = 'en' | 'ru' | 'zh';

const translations: Record<Locale, Record<string, string>> = {
	en: {
		'nav.connect': 'Connect',
		'nav.servers': 'Servers',
		'nav.settings': 'Settings',

		'status.connected': 'Connected',
		'status.disconnected': 'Disconnected',
		'status.connecting': 'Connecting...',
		'status.reconnecting': 'Reconnecting...',
		'status.starting': 'Starting Burrow...',
		'status.daemon_failed': 'Could not start the VPN daemon.',
		'status.daemon_failed_hint': 'Please restart the application.',
		'status.daemon_error': 'Cannot connect to Burrow daemon',

		'stats.uptime': 'Uptime',
		'stats.upload': 'Upload',
		'stats.download': 'Download',

		'detail.server': 'Server',
		'detail.protocol': 'Protocol',
		'detail.mode': 'Mode',
		'detail.kill_switch': 'Kill Switch',
		'detail.enabled': 'Enabled',
		'detail.disabled': 'Disabled',
		'detail.vpn_all': 'VPN (all traffic)',
		'detail.proxy_only': 'Proxy only',

		'pref.vpn_mode': 'VPN Mode',
		'pref.vpn_mode_on': 'All apps protected (recommended)',
		'pref.vpn_mode_off': 'Only configured apps use VPN',
		'pref.kill_switch': 'Kill Switch',
		'pref.kill_switch_desc': 'Blocks ALL internet if VPN drops — prevents unprotected browsing',
		'pref.auto_connect': 'Auto-Connect',
		'pref.auto_connect_desc': 'Auto-connect on app start, auto-reconnect on drops',

		'server.title': 'Servers',
		'server.add_label': 'Add server from invite link',
		'server.add_placeholder': 'burrow://connect/...',
		'server.add_btn': 'Add',
		'server.switch': 'Switch',
		'server.adding': 'Adding...',
		'server.remove': 'Remove',
		'server.remove_confirm': 'Remove server "{name}"?',
		'server.none': 'No servers configured',
		'server.none_hint': 'Paste an invite link above to add your first server',
		'server.add_link': 'Add a server',
		'server.daemon_error': 'Cannot reach local daemon',

		'settings.title': 'Settings',
		'settings.preferences': 'Preferences',
		'settings.proxy_config': 'Proxy Configuration',
		'settings.proxy_hint': 'When VPN Mode is off, configure apps to use these proxies:',
		'settings.about': 'About',
		'settings.version': 'Version',
		'settings.config': 'Config',
		'settings.language': 'Language',
		'settings.split_tunnel': 'Split Tunneling',
		'settings.split_tunnel_enable': 'Enable Split Tunneling',
		'settings.split_tunnel_desc': 'Route selected traffic directly, bypassing VPN',
		'settings.bypass_domains': 'Bypass Domains (one per line)',
		'settings.bypass_ips': 'Bypass IPs / CIDR (one per line)',
		'settings.save_rules': 'Save Rules',

		'onboarding.welcome': 'Welcome to Burrow',
		'onboarding.subtitle': 'Private, fast, and censorship-resistant VPN',
		'onboarding.step1': 'Get an invite link from your server administrator',
		'onboarding.step2': 'Paste it below to add your server',
		'onboarding.step3': 'Tap connect — that\'s it',
		'onboarding.paste_label': 'Paste your invite link',
		'onboarding.get_started': 'Get Started',
		'onboarding.continue': 'Add & Connect',
		'onboarding.skip': 'I\'ll do this later',
		'onboarding.back': 'Back',

		'server.select_default': 'Last used',
		'server.added': 'Server added',

		'error.retry': 'Retry',
		'error.permission': 'Administrator rights required for VPN mode',
		'error.timeout': 'Connection timed out',
		'error.unreachable': 'Server is unreachable',
		'error.port_in_use': 'Port 1080 is already in use',
		'error.dns': 'Cannot resolve server address',
		'error.tls': 'Secure connection failed',
		'error.already_connected': 'Already connected',
		'error.no_server': 'No server configured',
		'error.invalid_invite': 'Invalid invite link',
		'error.invalid_request': 'Invalid request',
		'error.server_not_found': 'Server not found',
		'error.tunnel_failed': 'Failed to start tunnel',
		'error.unknown': 'Connection error',
	},

	ru: {
		'nav.connect': 'Подключение',
		'nav.servers': 'Серверы',
		'nav.settings': 'Настройки',

		'status.connected': 'Подключено',
		'status.disconnected': 'Отключено',
		'status.connecting': 'Подключение...',
		'status.reconnecting': 'Переподключение...',
		'status.starting': 'Запуск Burrow...',
		'status.daemon_failed': 'Не удалось запустить VPN-демон.',
		'status.daemon_failed_hint': 'Перезапустите приложение.',
		'status.daemon_error': 'Нет связи с демоном Burrow',

		'stats.uptime': 'Время работы',
		'stats.upload': 'Отправлено',
		'stats.download': 'Получено',

		'detail.server': 'Сервер',
		'detail.protocol': 'Протокол',
		'detail.mode': 'Режим',
		'detail.kill_switch': 'Kill Switch',
		'detail.enabled': 'Включён',
		'detail.disabled': 'Выключен',
		'detail.vpn_all': 'VPN (весь трафик)',
		'detail.proxy_only': 'Только прокси',

		'pref.vpn_mode': 'Режим VPN',
		'pref.vpn_mode_on': 'Все приложения защищены (рекомендуется)',
		'pref.vpn_mode_off': 'Только настроенные приложения',
		'pref.kill_switch': 'Kill Switch',
		'pref.kill_switch_desc': 'Блокирует ВЕСЬ интернет при обрыве VPN — защита от утечек',
		'pref.auto_connect': 'Автоподключение',
		'pref.auto_connect_desc': 'Автоподключение при запуске и переподключение при обрыве',

		'server.title': 'Серверы',
		'server.add_label': 'Добавить сервер по инвайт-ссылке',
		'server.add_placeholder': 'burrow://connect/...',
		'server.add_btn': 'Добавить',
		'server.switch': 'Переключить',
		'server.adding': 'Добавление...',
		'server.remove': 'Удалить',
		'server.remove_confirm': 'Удалить сервер "{name}"?',
		'server.none': 'Нет настроенных серверов',
		'server.none_hint': 'Вставьте инвайт-ссылку выше, чтобы добавить первый сервер',
		'server.add_link': 'Добавить сервер',
		'server.daemon_error': 'Нет связи с локальным демоном',

		'settings.title': 'Настройки',
		'settings.preferences': 'Параметры',
		'settings.proxy_config': 'Настройки прокси',
		'settings.proxy_hint': 'При выключенном VPN-режиме настройте приложения на эти прокси:',
		'settings.about': 'О программе',
		'settings.version': 'Версия',
		'settings.config': 'Конфигурация',
		'settings.language': 'Язык',
		'settings.split_tunnel': 'Раздельное туннелирование',
		'settings.split_tunnel_enable': 'Раздельное туннелирование',
		'settings.split_tunnel_desc': 'Направлять выбранный трафик напрямую, минуя VPN',
		'settings.bypass_domains': 'Домены напрямую (по одному в строке)',
		'settings.bypass_ips': 'IP / CIDR напрямую (по одному в строке)',
		'settings.save_rules': 'Сохранить правила',

		'onboarding.welcome': 'Добро пожаловать в Burrow',
		'onboarding.subtitle': 'Приватный, быстрый VPN для обхода блокировок',
		'onboarding.step1': 'Получите инвайт-ссылку от администратора сервера',
		'onboarding.step2': 'Вставьте её ниже, чтобы добавить сервер',
		'onboarding.step3': 'Нажмите подключиться — готово',
		'onboarding.paste_label': 'Вставьте инвайт-ссылку',
		'onboarding.get_started': 'Начать',
		'onboarding.continue': 'Добавить и подключить',
		'onboarding.skip': 'Позже',
		'onboarding.back': 'Назад',

		'server.select_default': 'Последний использованный',
		'server.added': 'Сервер добавлен',

		'error.retry': 'Повторить',
		'error.permission': 'Требуются права администратора для VPN-режима',
		'error.timeout': 'Время подключения истекло',
		'error.unreachable': 'Сервер недоступен',
		'error.port_in_use': 'Порт 1080 уже занят',
		'error.dns': 'Не удаётся разрешить адрес сервера',
		'error.tls': 'Ошибка защищённого соединения',
		'error.already_connected': 'Уже подключено',
		'error.no_server': 'Сервер не настроен',
		'error.invalid_invite': 'Неверная инвайт-ссылка',
		'error.invalid_request': 'Неверный запрос',
		'error.server_not_found': 'Сервер не найден',
		'error.tunnel_failed': 'Не удалось запустить туннель',
		'error.unknown': 'Ошибка подключения',
	},

	zh: {
		'nav.connect': '连接',
		'nav.servers': '服务器',
		'nav.settings': '设置',

		'status.connected': '已连接',
		'status.disconnected': '未连接',
		'status.connecting': '连接中...',
		'status.reconnecting': '重新连接中...',
		'status.starting': '启动 Burrow...',
		'status.daemon_failed': '无法启动 VPN 守护进程。',
		'status.daemon_failed_hint': '请重新启动应用程序。',
		'status.daemon_error': '无法连接 Burrow 守护进程',

		'stats.uptime': '运行时间',
		'stats.upload': '上传',
		'stats.download': '下载',

		'detail.server': '服务器',
		'detail.protocol': '协议',
		'detail.mode': '模式',
		'detail.kill_switch': '断网保护',
		'detail.enabled': '已启用',
		'detail.disabled': '已禁用',
		'detail.vpn_all': 'VPN（全部流量）',
		'detail.proxy_only': '仅代理',

		'pref.vpn_mode': 'VPN 模式',
		'pref.vpn_mode_on': '所有应用受保护（推荐）',
		'pref.vpn_mode_off': '仅配置的应用使用 VPN',
		'pref.kill_switch': '断网保护',
		'pref.kill_switch_desc': 'VPN 断开时阻止所有上网 — 防止数据泄露',
		'pref.auto_connect': '自动连接',
		'pref.auto_connect_desc': '启动时自动连接，断开时自动重连',

		'server.title': '服务器',
		'server.add_label': '通过邀请链接添加服务器',
		'server.add_placeholder': 'burrow://connect/...',
		'server.add_btn': '添加',
		'server.switch': '切换',
		'server.adding': '添加中...',
		'server.remove': '移除',
		'server.remove_confirm': '确认移除服务器 "{name}"？',
		'server.none': '没有配置服务器',
		'server.none_hint': '在上方粘贴邀请链接以添加第一个服务器',
		'server.add_link': '添加服务器',
		'server.daemon_error': '无法连接本地守护进程',

		'settings.title': '设置',
		'settings.preferences': '偏好设置',
		'settings.proxy_config': '代理配置',
		'settings.proxy_hint': '关闭 VPN 模式时，配置应用程序使用以下代理：',
		'settings.about': '关于',
		'settings.version': '版本',
		'settings.config': '配置',
		'settings.language': '语言',
		'settings.split_tunnel': '分流',
		'settings.split_tunnel_enable': '启用分流',
		'settings.split_tunnel_desc': '将选定流量直接路由，绕过 VPN',
		'settings.bypass_domains': '直连域名（每行一个）',
		'settings.bypass_ips': '直连 IP / CIDR（每行一个）',
		'settings.save_rules': '保存规则',

		'onboarding.welcome': '欢迎使用 Burrow',
		'onboarding.subtitle': '私密、快速、抗审查的 VPN',
		'onboarding.step1': '从服务器管理员获取邀请链接',
		'onboarding.step2': '将其粘贴到下方以添加服务器',
		'onboarding.step3': '点击连接——完成',
		'onboarding.paste_label': '粘贴邀请链接',
		'onboarding.get_started': '开始使用',
		'onboarding.continue': '添加并连接',
		'onboarding.skip': '稍后再说',
		'onboarding.back': '返回',

		'server.select_default': '上次使用的',
		'server.added': '服务器已添加',

		'error.retry': '重试',
		'error.permission': 'VPN 模式需要管理员权限',
		'error.timeout': '连接超时',
		'error.unreachable': '服务器不可达',
		'error.port_in_use': '端口 1080 已被占用',
		'error.dns': '无法解析服务器地址',
		'error.tls': '安全连接失败',
		'error.already_connected': '已经连接',
		'error.no_server': '未配置服务器',
		'error.invalid_invite': '无效的邀请链接',
		'error.invalid_request': '无效请求',
		'error.server_not_found': '找不到服务器',
		'error.tunnel_failed': '无法启动隧道',
		'error.unknown': '连接错误',
	},
};

function detectLocale(): Locale {
	if (typeof localStorage !== 'undefined') {
		const saved = localStorage.getItem('burrow_locale') as Locale | null;
		if (saved && (saved === 'en' || saved === 'ru' || saved === 'zh')) return saved;
	}
	if (typeof navigator === 'undefined') return 'en';
	const lang = navigator.language.toLowerCase();
	if (lang.startsWith('ru')) return 'ru';
	if (lang.startsWith('zh')) return 'zh';
	return 'en';
}

let _locale = $state<Locale>(detectLocale());

export const i18n = {
	get locale() {
		return _locale;
	},
	set locale(v: Locale) {
		_locale = v;
		if (typeof localStorage !== 'undefined') {
			localStorage.setItem('burrow_locale', v);
		}
	},
	get locales(): { code: Locale; label: string }[] {
		return [
			{ code: 'en', label: 'English' },
			{ code: 'ru', label: 'Русский' },
			{ code: 'zh', label: '中文' },
		];
	},
	t(key: string, params?: Record<string, string>): string {
		let text = translations[_locale]?.[key] ?? translations.en[key] ?? key;
		if (params) {
			for (const [k, v] of Object.entries(params)) {
				text = text.replace(`{${k}}`, v);
			}
		}
		return text;
	},
};

export function t(key: string, params?: Record<string, string>): string {
	return i18n.t(key, params);
}
