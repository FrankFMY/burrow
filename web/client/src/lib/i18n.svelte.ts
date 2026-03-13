type Locale = 'en' | 'ru' | 'zh';

const translations: Record<Locale, Record<string, string>> = {
	en: {
		'app.name': 'Burrow',
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
		'pref.vpn_mode_on': 'All traffic through VPN',
		'pref.vpn_mode_off': 'Manual proxy (SOCKS5/HTTP)',
		'pref.kill_switch': 'Kill Switch',
		'pref.kill_switch_desc': 'Block all traffic if VPN disconnects',
		'pref.auto_connect': 'Auto-Connect',
		'pref.auto_connect_desc': 'Connect automatically when app opens',

		'server.title': 'Servers',
		'server.add_label': 'Add server from invite link',
		'server.add_placeholder': 'burrow://connect/...',
		'server.add_btn': 'Add',
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

		'onboarding.welcome': 'Welcome to Burrow',
		'onboarding.subtitle': 'Private, fast, and censorship-resistant VPN',
		'onboarding.step1': 'Get an invite link from your server administrator',
		'onboarding.step2': 'Paste it below to add your server',
		'onboarding.step3': 'Tap connect — that\'s it',
		'onboarding.paste_label': 'Paste your invite link',
		'onboarding.continue': 'Add & Connect',
		'onboarding.skip': 'I\'ll do this later',

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
	},

	ru: {
		'app.name': 'Burrow',
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
		'pref.vpn_mode_on': 'Весь трафик через VPN',
		'pref.vpn_mode_off': 'Ручной прокси (SOCKS5/HTTP)',
		'pref.kill_switch': 'Kill Switch',
		'pref.kill_switch_desc': 'Блокировать трафик при отключении VPN',
		'pref.auto_connect': 'Автоподключение',
		'pref.auto_connect_desc': 'Подключаться при запуске приложения',

		'server.title': 'Серверы',
		'server.add_label': 'Добавить сервер по инвайт-ссылке',
		'server.add_placeholder': 'burrow://connect/...',
		'server.add_btn': 'Добавить',
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

		'onboarding.welcome': 'Добро пожаловать в Burrow',
		'onboarding.subtitle': 'Приватный, быстрый VPN для обхода блокировок',
		'onboarding.step1': 'Получите инвайт-ссылку от администратора сервера',
		'onboarding.step2': 'Вставьте её ниже, чтобы добавить сервер',
		'onboarding.step3': 'Нажмите подключиться — готово',
		'onboarding.paste_label': 'Вставьте инвайт-ссылку',
		'onboarding.continue': 'Добавить и подключить',
		'onboarding.skip': 'Позже',

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
	},

	zh: {
		'app.name': 'Burrow',
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
		'pref.vpn_mode_on': '所有流量通过 VPN',
		'pref.vpn_mode_off': '手动代理 (SOCKS5/HTTP)',
		'pref.kill_switch': '断网保护',
		'pref.kill_switch_desc': 'VPN 断开时阻止所有流量',
		'pref.auto_connect': '自动连接',
		'pref.auto_connect_desc': '启动应用时自动连接',

		'server.title': '服务器',
		'server.add_label': '通过邀请链接添加服务器',
		'server.add_placeholder': 'burrow://connect/...',
		'server.add_btn': '添加',
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

		'onboarding.welcome': '欢迎使用 Burrow',
		'onboarding.subtitle': '私密、快速、抗审查的 VPN',
		'onboarding.step1': '从服务器管理员获取邀请链接',
		'onboarding.step2': '将其粘贴到下方以添加服务器',
		'onboarding.step3': '点击连接——完成',
		'onboarding.paste_label': '粘贴邀请链接',
		'onboarding.continue': '添加并连接',
		'onboarding.skip': '稍后再说',

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
	},
};

function detectLocale(): Locale {
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
