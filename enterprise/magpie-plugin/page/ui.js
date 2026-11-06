const MESSAGES = {
  en: {
    title: "Enterprise resources",
    subtitle: "This computer's enterprise sign-in and signed resource sync.",
    syncNow: "Sync now",
    syncing: "Syncing…",
    device: "Device",
    sync: "Sync",
    resources: "Resources",
    joined: "Joined",
    notJoined: "Not joined",
    noCredential: "No device credential was found. Join this computer first.",
    unreadableCredential: "The device credential could not be read ({reason}).",
    invalidCredential: "The device credential is invalid ({reason}).",
    noConfig: "Enterprise resource sync is not configured on this computer.",
    unreadableConfig: "The resource sync configuration could not be read ({reason}).",
    invalidConfig: "The resource sync configuration is invalid ({reason}).",
    configHint: "Ask your administrator for enterprise-sync.json in the Magpie Enterprise state folder.",
    tokenExpires: "Device credential expires {time}",
    gateway: "Gateway {url}",
    never: "Never synced",
    synced: "Synced",
    syncError: "Last sync failed",
    syncUnknown: "The sync state could not be read ({reason}).",
    notConfigured: "Not configured",
    lastSuccess: "Last success {time}",
    lastAttempt: "Last attempt {time}",
    revision: "Revision {revision}",
    noRevision: "No successful revision yet",
    lastError: "Last error: {code}",
    resourcesCount: "{count} total",
    noResources: "The enterprise has not assigned resources to this device.",
    noResourcesYet: "Sync this device to fetch its assigned resources.",
    resourcesConfigMissing: "Configure resource sync before resources can be shown.",
    kindResource: "Resource",
    deliveryForced: "Forced",
    deliveryRecommended: "Recommended",
    statusInstalled: "Installed",
    statusDrift: "Changed",
    statusMissing: "Missing",
    statusDisabled: "Turned off",
    statusOrphaned: "No longer assigned",
    version: "v{version}",
    noVersion: "no version",
    noticeJoinFirst: "Join this computer first: run join-enterprise.ps1 from the Magpie Enterprise package.",
    noticeConfig: "Resource sync is not configured. Ask your administrator for enterprise-sync.json.",
    noticeSyncError: "The last sync failed ({code}). Installed resources are kept.",
    noticeOffline: "The control plane is unreachable ({code}). Installed resources are kept.",
    noticeSyncStarted: "Syncing enterprise resources…",
    noticeUpToDate: "Everything is up to date.",
    noticeSynced: "Sync complete: {installed} installed or updated, {unchanged} unchanged, {skipped} skipped.",
    noticeBusy: "A sync is already running on this computer.",
    noticeFailed: "Sync failed ({code}). Installed resources are kept.",
    noticeReportSkipped: "Resources synced, but the result could not be reported ({reason}).",
    serviceUnreachable: "The enterprise service is not reachable. Is the plugin host running?",
    requestFailed: "The enterprise service answered {status}.",
    pageExpired: "This enterprise page has expired. Close and open it again.",
    badgeOk: "OK",
    badgeCheck: "Check",
    badgePending: "Pending",
    badgeOff: "Off",
    badgeJoined: "Joined",
    badgeNotJoined: "Not joined",
    unknownReason: "unknown",
    err_desired_state_unavailable: "the control plane is unreachable",
    err_sync_credential_unavailable: "a sync credential could not be issued",
    err_sync_locked: "another sync is running",
    err_sync_busy: "another sync is running",
    err_invalid_state: "the sync state is invalid",
    err_content_invalid: "resource content failed verification",
    err_manifest_invalid: "the resource manifest is invalid",
    err_manifest_key_unknown: "the signing key is not trusted",
    err_install_failed: "the resource could not be installed",
    err_state_write_failed: "the sync state could not be written",
    err_client_sync_module_missing: "the client sync core was not found",
    err_sync_report_rejected: "the control plane rejected the report",
    err_sync_aborted: "the sync was aborted",
    err_desired_state_invalid: "the desired state is invalid",
    err_path_symlink: "a symbolic link was refused",
    err_path_traversal: "a path traversal was refused",
    err_invalid_config: "the enterprise sync configuration is invalid",
    err_internal_error: "an internal error occurred",
    err_http_error: "the request failed",
    err_not_joined: "this computer is not joined",
    err_sync_not_configured: "resource sync is not configured",
    err_forbidden_token: "the page token was refused",
    err_unknown: "unknown error",
  },
  zh: {
    title: "企业资源",
    subtitle: "这台电脑的企业登录与已签名资源同步状态。",
    syncNow: "立即同步",
    syncing: "正在同步…",
    device: "设备",
    sync: "同步",
    resources: "资源",
    joined: "已加入",
    notJoined: "未加入",
    noCredential: "未找到设备凭据。请先加入企业。",
    unreadableCredential: "无法读取设备凭据（{reason}）。",
    invalidCredential: "设备凭据无效（{reason}）。",
    noConfig: "这台电脑尚未配置企业资源同步。",
    unreadableConfig: "无法读取同步配置（{reason}）。",
    invalidConfig: "同步配置无效（{reason}）。",
    configHint: "请联系管理员，将 enterprise-sync.json 放到 Magpie Enterprise 状态目录。",
    tokenExpires: "设备凭据到期：{time}",
    gateway: "网关：{url}",
    never: "从未同步",
    synced: "已同步",
    syncError: "上次同步失败",
    syncUnknown: "无法读取同步状态（{reason}）。",
    notConfigured: "未配置",
    lastSuccess: "上次成功：{time}",
    lastAttempt: "上次尝试：{time}",
    revision: "版本：{revision}",
    noRevision: "还没有成功同步的版本",
    lastError: "上次错误：{code}",
    resourcesCount: "共 {count} 项",
    noResources: "企业尚未给这台设备分配资源。",
    noResourcesYet: "点击“立即同步”获取分配给这台设备的资源。",
    resourcesConfigMissing: "配置同步后才能查看资源。",
    kindResource: "资源",
    deliveryForced: "强制",
    deliveryRecommended: "推荐",
    statusInstalled: "已安装",
    statusDrift: "已变更",
    statusMissing: "缺失",
    statusDisabled: "已关闭",
    statusOrphaned: "已不再分配",
    version: "v{version}",
    noVersion: "无版本",
    noticeJoinFirst: "请先加入企业：运行企业包里的 join-enterprise.ps1。",
    noticeConfig: "尚未配置资源同步。请联系管理员获取 enterprise-sync.json。",
    noticeSyncError: "上次同步失败（{code}），已安装资源继续保留。",
    noticeOffline: "无法连接控制面（{code}），已安装资源继续保留。",
    noticeSyncStarted: "正在同步企业资源…",
    noticeUpToDate: "所有资源都是最新的。",
    noticeSynced: "同步完成：{installed} 项安装或更新，{unchanged} 项未变，{skipped} 项跳过。",
    noticeBusy: "这台电脑已有同步正在进行。",
    noticeFailed: "同步失败（{code}），已安装资源继续保留。",
    noticeReportSkipped: "资源已同步，但结果上报失败（{reason}）。",
    serviceUnreachable: "无法连接企业服务。插件宿主是否正在运行？",
    requestFailed: "企业服务返回 {status}。",
    pageExpired: "企业页面已失效，请关闭后重新打开。",
    badgeOk: "正常",
    badgeCheck: "需检查",
    badgePending: "待同步",
    badgeOff: "未启用",
    badgeJoined: "已加入",
    badgeNotJoined: "未加入",
    unknownReason: "未知",
    err_desired_state_unavailable: "控制面不可达",
    err_sync_credential_unavailable: "无法签发同步凭证",
    err_sync_locked: "另一个同步正在进行",
    err_sync_busy: "另一个同步正在进行",
    err_invalid_state: "同步状态无效",
    err_content_invalid: "资源内容校验失败",
    err_manifest_invalid: "资源清单无效",
    err_manifest_key_unknown: "签名密钥不受信任",
    err_install_failed: "资源安装失败",
    err_state_write_failed: "无法写入同步状态",
    err_client_sync_module_missing: "找不到客户端同步核心",
    err_sync_report_rejected: "控制面拒绝了上报",
    err_sync_aborted: "同步已中止",
    err_desired_state_invalid: "控制面下发的状态无效",
    err_path_symlink: "已拒绝符号链接",
    err_path_traversal: "已拒绝路径穿越",
    err_invalid_config: "企业同步配置无效",
    err_internal_error: "发生内部错误",
    err_http_error: "请求失败",
    err_not_joined: "这台电脑尚未加入企业",
    err_sync_not_configured: "尚未配置资源同步",
    err_forbidden_token: "页面校验失败",
    err_unknown: "未知错误",
  },
  "zh-TW": {
    title: "企業資源",
    subtitle: "這台電腦的企業登入與已簽章資源同步狀態。",
    syncNow: "立即同步",
    syncing: "正在同步…",
    device: "裝置",
    sync: "同步",
    resources: "資源",
    joined: "已加入",
    notJoined: "未加入",
    noCredential: "找不到裝置憑證。請先加入企業。",
    unreadableCredential: "無法讀取裝置憑證（{reason}）。",
    invalidCredential: "裝置憑證無效（{reason}）。",
    noConfig: "這台電腦尚未設定企業資源同步。",
    unreadableConfig: "無法讀取同步設定（{reason}）。",
    invalidConfig: "同步設定無效（{reason}）。",
    configHint: "請聯絡管理員，將 enterprise-sync.json 放到 Magpie Enterprise 狀態目錄。",
    tokenExpires: "裝置憑證到期：{time}",
    gateway: "閘道：{url}",
    never: "從未同步",
    synced: "已同步",
    syncError: "上次同步失敗",
    syncUnknown: "無法讀取同步狀態（{reason}）。",
    notConfigured: "未設定",
    lastSuccess: "上次成功：{time}",
    lastAttempt: "上次嘗試：{time}",
    revision: "版本：{revision}",
    noRevision: "還沒有成功同步的版本",
    lastError: "上次錯誤：{code}",
    resourcesCount: "共 {count} 項",
    noResources: "企業尚未指派資源給這台裝置。",
    noResourcesYet: "點擊「立即同步」取得指派給這台裝置的資源。",
    resourcesConfigMissing: "設定同步後才能查看資源。",
    kindResource: "資源",
    deliveryForced: "強制",
    deliveryRecommended: "推薦",
    statusInstalled: "已安裝",
    statusDrift: "已變更",
    statusMissing: "缺少",
    statusDisabled: "已關閉",
    statusOrphaned: "已不再指派",
    version: "v{version}",
    noVersion: "無版本",
    noticeJoinFirst: "請先加入企業：執行企業套件裡的 join-enterprise.ps1。",
    noticeConfig: "尚未設定資源同步。請聯絡管理員取得 enterprise-sync.json。",
    noticeSyncError: "上次同步失敗（{code}），已安裝資源繼續保留。",
    noticeOffline: "無法連線控制面（{code}），已安裝資源繼續保留。",
    noticeSyncStarted: "正在同步企業資源…",
    noticeUpToDate: "所有資源都是最新的。",
    noticeSynced: "同步完成：{installed} 項安裝或更新，{unchanged} 項未變，{skipped} 項略過。",
    noticeBusy: "這台電腦已有同步正在進行。",
    noticeFailed: "同步失敗（{code}），已安裝資源繼續保留。",
    noticeReportSkipped: "資源已同步，但結果回報失敗（{reason}）。",
    serviceUnreachable: "無法連線企業服務。外掛宿主是否正在執行？",
    requestFailed: "企業服務傳回 {status}。",
    pageExpired: "企業頁面已失效，請關閉後重新開啟。",
    badgeOk: "正常",
    badgeCheck: "需檢查",
    badgePending: "待同步",
    badgeOff: "未啟用",
    badgeJoined: "已加入",
    badgeNotJoined: "未加入",
    unknownReason: "未知",
    err_desired_state_unavailable: "控制面不可達",
    err_sync_credential_unavailable: "無法簽發同步憑證",
    err_sync_locked: "另一個同步正在進行",
    err_sync_busy: "另一個同步正在進行",
    err_invalid_state: "同步狀態無效",
    err_content_invalid: "資源內容驗證失敗",
    err_manifest_invalid: "資源清單無效",
    err_manifest_key_unknown: "簽章金鑰不受信任",
    err_install_failed: "資源安裝失敗",
    err_state_write_failed: "無法寫入同步狀態",
    err_client_sync_module_missing: "找不到用戶端同步核心",
    err_sync_report_rejected: "控制面拒絕了回報",
    err_sync_aborted: "同步已中止",
    err_desired_state_invalid: "控制面下發的狀態無效",
    err_path_symlink: "已拒絕符號連結",
    err_path_traversal: "已拒絕路徑穿越",
    err_invalid_config: "企業同步設定無效",
    err_internal_error: "發生內部錯誤",
    err_http_error: "請求失敗",
    err_not_joined: "這台電腦尚未加入企業",
    err_sync_not_configured: "尚未設定資源同步",
    err_forbidden_token: "頁面驗證失敗",
    err_unknown: "未知錯誤",
  },
  ja: {
    title: "エンタープライズリソース",
    subtitle: "このコンピューターの企業サインインと署名済みリソース同期。",
    syncNow: "今すぐ同期",
    syncing: "同期中…",
    device: "デバイス",
    sync: "同期",
    resources: "リソース",
    joined: "参加済み",
    notJoined: "未参加",
    noCredential: "デバイス資格情報がありません。先に企業へ参加してください。",
    unreadableCredential: "デバイス資格情報を読み取れません（{reason}）。",
    invalidCredential: "デバイス資格情報が無効です（{reason}）。",
    noConfig: "このコンピューターではリソース同期が設定されていません。",
    unreadableConfig: "リソース同期の設定を読み取れません（{reason}）。",
    invalidConfig: "リソース同期の設定が無効です（{reason}）。",
    configHint: "管理者に enterprise-sync.json を Magpie Enterprise の状態フォルダーへ置いてもらってください。",
    tokenExpires: "デバイス資格情報の有効期限 {time}",
    gateway: "ゲートウェイ {url}",
    never: "未同期",
    synced: "同期済み",
    syncError: "前回の同期に失敗しました",
    syncUnknown: "同期状態を読み取れません（{reason}）。",
    notConfigured: "未設定",
    lastSuccess: "前回の成功 {time}",
    lastAttempt: "前回の試行 {time}",
    revision: "リビジョン {revision}",
    noRevision: "成功したリビジョンはまだありません",
    lastError: "前回のエラー: {code}",
    resourcesCount: "合計 {count}",
    noResources: "このデバイスに割り当てられたリソースはありません。",
    noResourcesYet: "このデバイスを同期して割り当て済みリソースを取得してください。",
    resourcesConfigMissing: "リソースを表示するには同期を設定してください。",
    kindResource: "リソース",
    deliveryForced: "必須",
    deliveryRecommended: "推奨",
    statusInstalled: "インストール済み",
    statusDrift: "変更あり",
    statusMissing: "不足",
    statusDisabled: "無効",
    statusOrphaned: "割り当て解除",
    version: "v{version}",
    noVersion: "バージョンなし",
    noticeJoinFirst: "先に企業へ参加してください：企業パッケージの join-enterprise.ps1 を実行します。",
    noticeConfig: "リソース同期が設定されていません。管理者に enterprise-sync.json を確認してください。",
    noticeSyncError: "前回の同期に失敗しました（{code}）。インストール済みリソースは保持されます。",
    noticeOffline: "コントロールプレーンに接続できません（{code}）。インストール済みリソースは保持されます。",
    noticeSyncStarted: "エンタープライズリソースを同期しています…",
    noticeUpToDate: "すべて最新です。",
    noticeSynced: "同期完了：{installed} 件をインストールまたは更新、{unchanged} 件は変更なし、{skipped} 件をスキップしました。",
    noticeBusy: "このコンピューターでは既に同期が実行中です。",
    noticeFailed: "同期に失敗しました（{code}）。インストール済みリソースは保持されます。",
    noticeReportSkipped: "リソースは同期されましたが、結果を報告できませんでした（{reason}）。",
    serviceUnreachable: "エンタープライズサービスに接続できません。プラグインホストは動作していますか？",
    requestFailed: "エンタープライズサービスが {status} を返しました。",
    pageExpired: "このエンタープライズページは期限切れです。閉じて開き直してください。",
    badgeOk: "正常",
    badgeCheck: "確認",
    badgePending: "待機",
    badgeOff: "オフ",
    badgeJoined: "参加済み",
    badgeNotJoined: "未参加",
    unknownReason: "不明",
  },
  de: {
    title: "Unternehmensressourcen",
    subtitle: "Unternehmensanmeldung und signierte Ressourcensynchronisierung dieses Computers.",
    syncNow: "Jetzt synchronisieren",
    syncing: "Synchronisierung…",
    device: "Gerät",
    sync: "Synchronisierung",
    resources: "Ressourcen",
    joined: "Beigetreten",
    notJoined: "Nicht beigetreten",
    noCredential: "Keine Geräteanmeldedaten gefunden. Tritt zuerst dem Unternehmen bei.",
    unreadableCredential: "Die Geräteanmeldedaten konnten nicht gelesen werden ({reason}).",
    invalidCredential: "Die Geräteanmeldedaten sind ungültig ({reason}).",
    noConfig: "Die Unternehmensressourcen-Synchronisierung ist auf diesem Computer nicht eingerichtet.",
    unreadableConfig: "Die Synchronisierungskonfiguration konnte nicht gelesen werden ({reason}).",
    invalidConfig: "Die Synchronisierungskonfiguration ist ungültig ({reason}).",
    configHint: "Bitte die Administration um enterprise-sync.json im Statusordner von Magpie Enterprise.",
    tokenExpires: "Geräteanmeldedaten laufen ab am {time}",
    gateway: "Gateway {url}",
    never: "Nie synchronisiert",
    synced: "Synchronisiert",
    syncError: "Letzte Synchronisierung fehlgeschlagen",
    syncUnknown: "Der Synchronisierungsstatus konnte nicht gelesen werden ({reason}).",
    notConfigured: "Nicht eingerichtet",
    lastSuccess: "Letzter Erfolg {time}",
    lastAttempt: "Letzter Versuch {time}",
    revision: "Revision {revision}",
    noRevision: "Noch keine erfolgreiche Revision",
    lastError: "Letzter Fehler: {code}",
    resourcesCount: "{count} gesamt",
    noResources: "Dem Gerät sind noch keine Ressourcen zugewiesen.",
    noResourcesYet: "Synchronisiere dieses Gerät, um die zugewiesenen Ressourcen zu laden.",
    resourcesConfigMissing: "Richte die Synchronisierung ein, bevor Ressourcen angezeigt werden.",
    kindResource: "Ressource",
    deliveryForced: "Erzwungen",
    deliveryRecommended: "Empfohlen",
    statusInstalled: "Installiert",
    statusDrift: "Geändert",
    statusMissing: "Fehlt",
    statusDisabled: "Ausgeschaltet",
    statusOrphaned: "Nicht mehr zugewiesen",
    version: "v{version}",
    noVersion: "keine Version",
    noticeJoinFirst: "Tritt zuerst bei: join-enterprise.ps1 aus dem Magpie-Enterprise-Paket ausführen.",
    noticeConfig: "Die Ressourcensynchronisierung ist nicht eingerichtet. Bitte die Administration um enterprise-sync.json.",
    noticeSyncError: "Die letzte Synchronisierung ist fehlgeschlagen ({code}). Installierte Ressourcen bleiben erhalten.",
    noticeOffline: "Die Steuerungsebene ist nicht erreichbar ({code}). Installierte Ressourcen bleiben erhalten.",
    noticeSyncStarted: "Unternehmensressourcen werden synchronisiert…",
    noticeUpToDate: "Alles ist aktuell.",
    noticeSynced: "Synchronisierung abgeschlossen: {installed} installiert oder aktualisiert, {unchanged} unverändert, {skipped} übersprungen.",
    noticeBusy: "Auf diesem Computer läuft bereits eine Synchronisierung.",
    noticeFailed: "Synchronisierung fehlgeschlagen ({code}). Installierte Ressourcen bleiben erhalten.",
    noticeReportSkipped: "Ressourcen wurden synchronisiert, aber das Ergebnis konnte nicht gemeldet werden ({reason}).",
    serviceUnreachable: "Der Unternehmensdienst ist nicht erreichbar. Läuft der Plugin-Host?",
    requestFailed: "Der Unternehmensdienst antwortete mit {status}.",
    pageExpired: "Diese Unternehmensseite ist abgelaufen. Schließen und erneut öffnen.",
    badgeOk: "OK",
    badgeCheck: "Prüfen",
    badgePending: "Ausstehend",
    badgeOff: "Aus",
    badgeJoined: "Beigetreten",
    badgeNotJoined: "Nicht beigetreten",
    unknownReason: "unbekannt",
  },
};

const LANG = document.documentElement.lang || "en";
const LOCALE = LANG === "zh" ? "zh-CN" : LANG;
const TOKEN = document.querySelector('meta[name="magpie-enterprise-token"]')?.content || "";
const dict = MESSAGES[LANG] || MESSAGES.en;

const ADMIN_MESSAGES = {
  en: {
    adminTitle: "Administrator",
    employee: "Employee",
    administrator: "Administrator",
    adminGateTitle: "Administrator mode",
    adminGateText: "Sign in with your management account to manage providers, routing and the enterprise gateway.",
    adminSignIn: "Sign in",
    adminSigningIn: "Waiting for the browser…",
    adminSignedInAs: "Signed in as {name}",
    adminExpires: "Session expires {time}",
    adminSignOut: "Sign out",
    adminRefresh: "Refresh",
    webConsole: "Web console",
    tabOverview: "Overview",
    tabProviders: "Providers",
    tabRouting: "Routing",
    tabGateway: "Gateway",
    tabResources: "Resources",
    tabUsage: "Usage",
    tabAudit: "Audit",
    auditTitle: "Collected content",
    auditCount: "{count} streams",
    auditEmpty: "No content was collected in this window.",
    auditUnavailable: "Your role cannot search collected content.",
    auditNote: "Reading a body needs an approval and a fresh sign-in, so it happens in the web console. This page shows what was collected, never the text.",
    auditUser: "user {user}",
    auditAgent: "agent {agent}",
    auditModel: "model {model}",
    auditBytes: "{bytes} bytes",
    auditClose: "Close",
    resTitle: "Resources",
    resEmpty: "The enterprise has not published any resources.",
    resCount: "{count} resources",
    resUpdated: "updated {time}",
    resDelivery: "delivery {mode}",
    resScope: "scope {scope}",
    resDetail: "Resource",
    resReleases: "Releases",
    resNoReleases: "This resource has no releases yet.",
    resClose: "Close",
    resVersion: "version {version}",
    resPublished: "published {time}",
    syncTitle: "Client sync",
    syncEmpty: "No device has reported its sync state yet.",
    syncCount: "{count} devices",
    syncInstalled: "{count} installed",
    syncDrift: "{count} drifted",
    syncReported: "reported {time}",
    syncUser: "user {user}",
    ovGateway: "Gateway",
    ovCalls: "Requests today",
    ovRecent: "Recent requests",
    providers: "Providers",
    providersEmpty: "The gateway has no providers yet.",
    providerAdd: "Add provider",
    providerEdit: "Edit provider",
    providerName: "Name",
    providerBase: "Base URL",
    providerKey: "API key",
    providerModels: "Models (comma separated, empty for all)",
    providerOff: "Turned off",
    save: "Save",
    cancel: "Cancel",
    delete: "Delete",
    edit: "Edit",
    routing: "Routing groups",
    routingEmpty: "The gateway has no routing groups you can edit.",
    gateway: "Enterprise gateway",
    gatewayModels: "Models",
    gatewayKeys: "Gateway keys",
    gatewayKeysEmpty: "The gateway has no caller keys.",
    gatewayDevices: "Devices",
    gatewayDevicesEmpty: "No devices have joined this enterprise yet.",
    deviceUser: "user {user}",
    deviceLastSeen: "last seen {time}",
    deviceStatus: "status {status}",
    keyResting: "resting ({why})",
    keyPrimary: "primary",
    keyWeight: "weight {weight}",
    memberResting: "resting ({why})",
    providerKeyEnable: "Enable",
    providerKeyDisable: "Disable",
    providerKeyPrimary: "Make primary",
    providerKeyNewValue: "Paste the key's new value. It is sent to the gateway and never shown again.",
    confirmRotateProviderKey: "Replace the key {name}? The old value stops working.",
    confirmRemoveProviderKey: "Remove the key {name}?",
    providerAddKeys: "Add keys (one per line)",
    keyAdd: "Add key",
    keyCreate: "Create",
    usage: "Requests",
    usageEmpty: "No requests have been recorded yet.",
    usageRequests: "Requests",
    usageSuccessful: "Successful",
    usageErrors: "Errors",
    usageTokens: "Tokens",
    usageCost: "Cost (USD)",
    usageUsers: "By user",
    usageUsersCount: "{count} users",
    usageUsersEmpty: "No user usage in this window.",
    usageChart: "Requests per {bucket}",
    usageChartEmpty: "No usage in this window.",
    usageUnavailable: "Usage summary is unavailable for your role.",
    noData: "Not available yet",
    requestsTotal: "{count} total",
    requestRow: "{model} → {provider}",
    requestMeta: "status {status} · {ms} ms · {tokens} tokens · {tries} tries",
    modelCount: "{count} models",
    keyStateSet: "Key set",
    keyStateMissing: "No key",
    keyStateSubscription: "Subscription",
    badgeLive: "Live",
    badgeOff: "Off",
    confirmDeleteProvider: "Delete provider {name}?",
    adminUnavailable: "The management console is not configured on this computer.",
    consoleAddress: "Management console address",
    consoleSave: "Save address",
    consoleSaved: "Address saved. Sign in to continue.",
    adminUnreachable: "The management console is unreachable.",
    adminExpired: "Your administrator session ended. Sign in again.",
    adminLoginOpened: "Complete the sign-in in the browser window that opened.",
    overviewCounts: "{providers} providers · {groups} groups · {keys} keys",
    overviewUsage: "{tokens} tokens · {cost}",
    requestAccount: "account {account}",
    requestKey: "key {key}",
    requestAgent: "agent {agent}",
    providerPreset: "preset {preset}",
    providerPresetField: "Preset (optional)",
    changeReason: "Change reason (audit)",
    changeReasonPrompt: "Why is this change being made? It is recorded in the audit log.",
    keyStateSetMany: "{count} keys",
    routingMembers: "{count} members",
    groupAdd: "Add routing group",
    groupEdit: "Edit routing group",
    groupId: "ID (lowercase letters, digits, dots, dashes)",
    groupName: "Name",
    groupMembers: "Members (one per line, in order)",
    groupMatch: "Match models (one per line, empty for all)",
    groupRouting: "Routing",
    groupAffinity: "Affinity",
    groupOff: "Turned off members (one per line)",
    groupRules: "Rules (JSON array)",
    groupWeights: "Weights (JSON object)",
    groupDisabled: "Disabled",
    invalidJson: "{field} is not valid JSON.",
    confirmDeleteGroup: "Delete routing group {name}?",
    keyReadOnly: "read-only",
    keyLimit: "{tokens} tokens per {period}",
    keyEdit: "Edit a gateway key",
    keyPolicyNote: "Changing a limit or the model allowlist is a high-risk action and needs an approval from the web console.",
    keyRotate: "Rotate",
    keyShownOnce: "Save this key now; it is shown once: {secret}",
    keySaveNow: "Save this key now; it is shown once.",
    invalidLimit: "The limit must be a non-negative number.",
    approvalNeeded: "This change needs an approval. Start it in the web console, then try again.",
    approvalPrompt: "Approval ID from the web console's approval centre:",
    confirmRotateKey: "Rotate the key for {name}? The old secret stops working.",
    confirmRemoveKey: "Remove the key {name}?",
    routeDetail: "Route",
    routeLoading: "Loading the route…",
    routeGone: "This route is no longer in the gateway's memory. Read the usage record instead.",
    detailRoute: "Route",
    detailTime: "Time",
    detailAgent: "Agent",
    detailModel: "Model",
    detailProvider: "Provider",
    detailStatus: "Status",
    detailMillis: "Duration",
    detailTTFT: "First token",
    detailTokens: "Output tokens",
    detailGroup: "Routing group",
    detailError: "Error",
    detailTries: "{count} attempts",
    detailSourceLive: "Source: the gateway's live trace.",
    detailSourceUsage: "Source: the usage ledger (after a restart the trace is gone).",
    adminConsoleHint: "Users, organizations, devices, approvals and audit stay in the web console.",
  },
  zh: {
    adminTitle: "管理员",
    employee: "员工",
    administrator: "管理员",
    adminGateTitle: "管理员模式",
    adminGateText: "使用管理账号登录，管理供应商、路由与企业网关。",
    adminSignIn: "登录",
    adminSigningIn: "正在等待浏览器完成登录…",
    adminSignedInAs: "已登录：{name}",
    adminExpires: "会话到期：{time}",
    adminSignOut: "退出",
    adminRefresh: "刷新",
    webConsole: "网页管理台",
    tabOverview: "总览",
    tabProviders: "供应商",
    tabRouting: "路由",
    tabGateway: "网关",
    tabResources: "资源",
    tabUsage: "用量",
    tabAudit: "审计",
    auditTitle: "已采集内容",
    auditCount: "{count} 条流",
    auditEmpty: "这个时间窗没有采集到内容。",
    auditUnavailable: "你的角色不能检索已采集内容。",
    auditNote: "读取正文需要审批和重新认证，所以只能在网页管理台进行。这里只展示采集元数据，从不显示正文。",
    auditUser: "用户 {user}",
    auditAgent: "Agent {agent}",
    auditModel: "模型 {model}",
    auditBytes: "{bytes} 字节",
    auditClose: "关闭",
    resTitle: "企业资源",
    resEmpty: "企业还没有发布任何资源。",
    resCount: "{count} 个资源",
    resUpdated: "更新于 {time}",
    resDelivery: "下发方式 {mode}",
    resScope: "范围 {scope}",
    resDetail: "资源详情",
    resReleases: "发布记录",
    resNoReleases: "这个资源还没有发布记录。",
    resClose: "关闭",
    resVersion: "版本 {version}",
    resPublished: "发布于 {time}",
    syncTitle: "客户端同步",
    syncEmpty: "还没有设备上报同步状态。",
    syncCount: "{count} 台设备",
    syncInstalled: "已安装 {count}",
    syncDrift: "漂移 {count}",
    syncReported: "上报于 {time}",
    syncUser: "用户 {user}",
    ovGateway: "网关",
    ovCalls: "今日请求",
    ovRecent: "最近调用",
    providers: "供应商",
    providersEmpty: "网关还没有供应商。",
    providerAdd: "添加供应商",
    providerEdit: "编辑供应商",
    providerName: "名称",
    providerBase: "Base URL",
    providerKey: "API Key",
    providerModels: "模型（英文逗号分隔，留空表示全部）",
    providerOff: "停用",
    save: "保存",
    cancel: "取消",
    delete: "删除",
    edit: "编辑",
    routing: "路由组",
    routingEmpty: "网关还没有可编辑的路由组。",
    gateway: "企业网关",
    gatewayModels: "模型",
    gatewayKeys: "Gateway Key",
    gatewayKeysEmpty: "网关还没有调用方 Key。",
    gatewayDevices: "员工设备",
    gatewayDevicesEmpty: "还没有设备加入企业。",
    deviceUser: "用户 {user}",
    deviceLastSeen: "最后在线 {time}",
    deviceStatus: "状态 {status}",
    keyResting: "休息中（{why}）",
    keyPrimary: "首要",
    keyWeight: "权重 {weight}",
    memberResting: "休息中（{why}）",
    providerKeyEnable: "启用",
    providerKeyDisable: "停用",
    providerKeyPrimary: "设为首要",
    providerKeyNewValue: "粘贴这个 Key 的新值。它只会发给网关，不会再显示。",
    confirmRotateProviderKey: "替换 {name} 的 Key？旧值将立即失效。",
    confirmRemoveProviderKey: "删除 Key {name}？",
    providerAddKeys: "添加 Key（每行一个）",
    keyAdd: "添加 Key",
    keyCreate: "创建",
    usage: "请求",
    usageEmpty: "还没有记录到请求。",
    usageRequests: "请求",
    usageSuccessful: "成功",
    usageErrors: "错误",
    usageTokens: "Token",
    usageCost: "费用（USD）",
    usageUsers: "按用户",
    usageUsersCount: "{count} 个用户",
    usageUsersEmpty: "这个时间窗没有用户用量。",
    usageChart: "每{bucket}请求",
    usageChartEmpty: "这个时间窗没有用量。",
    usageUnavailable: "你的角色看不到用量汇总。",
    noData: "暂无数据",
    requestsTotal: "共 {count} 条",
    requestRow: "{model} → {provider}",
    requestMeta: "状态 {status} · {ms} 毫秒 · {tokens} tokens · {tries} 次尝试",
    modelCount: "{count} 个模型",
    keyStateSet: "Key 已设置",
    keyStateMissing: "无 Key",
    keyStateSubscription: "订阅账号",
    badgeLive: "在线",
    badgeOff: "停用",
    confirmDeleteProvider: "删除供应商 {name}？",
    adminUnavailable: "这台电脑尚未配置网页管理台地址。",
    consoleAddress: "网页管理台地址",
    consoleSave: "保存地址",
    consoleSaved: "地址已保存，可以登录了。",
    adminUnreachable: "无法连接网页管理台。",
    adminExpired: "管理员会话已结束，请重新登录。",
    adminLoginOpened: "请在打开的浏览器窗口中完成登录。",
    overviewCounts: "{providers} 个供应商 · {groups} 个路由组 · {keys} 个 Key",
    overviewUsage: "{tokens} tokens · {cost}",
    requestAccount: "账号 {account}",
    requestKey: "Key {key}",
    requestAgent: "Agent {agent}",
    providerPreset: "预设 {preset}",
    providerPresetField: "预设（可选）",
    changeReason: "变更原因（审计）",
    changeReasonPrompt: "为什么要做这次变更？原因会写入审计日志。",
    keyStateSetMany: "{count} 个 Key",
    routingMembers: "{count} 个成员",
    groupAdd: "添加路由组",
    groupEdit: "编辑路由组",
    groupId: "ID（小写字母、数字、点、横线）",
    groupName: "名称",
    groupMembers: "成员（每行一个，按顺序）",
    groupMatch: "匹配模型（每行一个，留空表示全部）",
    groupRouting: "路由方式",
    groupAffinity: "亲和性",
    groupOff: "停用成员（每行一个）",
    groupRules: "规则（JSON 数组）",
    groupWeights: "权重（JSON 对象）",
    groupDisabled: "停用",
    invalidJson: "{field} 不是有效的 JSON。",
    confirmDeleteGroup: "删除路由组 {name}？",
    keyReadOnly: "只读",
    keyLimit: "每 {period} {tokens} tokens",
    keyEdit: "编辑 Gateway Key",
    keyPolicyNote: "修改额度或模型白名单属于高风险操作，需要在网页管理台发起审批。",
    keyRotate: "轮换",
    keyShownOnce: "请立即保存这个 Key，它只显示一次：{secret}",
    keySaveNow: "请立即保存这个 Key，它只显示一次。",
    invalidLimit: "额度必须是非负数字。",
    approvalNeeded: "此修改需要审批。请先在网页管理台发起审批，然后重试。",
    approvalPrompt: "网页管理台审批中心里的审批 ID：",
    confirmRotateKey: "轮换 {name} 的 Key？旧密钥将立即失效。",
    confirmRemoveKey: "删除 Key {name}？",
    routeDetail: "路由详情",
    routeLoading: "正在读取路由…",
    routeGone: "该路由已不在网关内存中，请改看用量记录。",
    detailRoute: "路由",
    detailTime: "时间",
    detailAgent: "Agent",
    detailModel: "模型",
    detailProvider: "供应商",
    detailStatus: "状态",
    detailMillis: "耗时",
    detailTTFT: "首字",
    detailTokens: "输出 tokens",
    detailGroup: "路由组",
    detailError: "错误",
    detailTries: "{count} 次尝试",
    detailSourceLive: "来源：网关实时 trace。",
    detailSourceUsage: "来源：用量台账（重启后内存 trace 已不在）。",
    adminConsoleHint: "用户、组织、设备、审批与审计仍在网页管理台。",
  },
  "zh-TW": {
    adminTitle: "管理員",
    employee: "員工",
    administrator: "管理員",
    adminGateTitle: "管理員模式",
    adminGateText: "使用管理帳號登入，管理供應商、路由與企業閘道。",
    adminSignIn: "登入",
    adminSigningIn: "正在等待瀏覽器完成登入…",
    adminSignedInAs: "已登入：{name}",
    adminExpires: "工作階段到期：{time}",
    adminSignOut: "登出",
    adminRefresh: "重新整理",
    webConsole: "網頁管理台",
    tabOverview: "總覽",
    tabProviders: "供應商",
    tabRouting: "路由",
    tabGateway: "閘道",
    tabResources: "資源",
    tabUsage: "用量",
    tabAudit: "稽核",
    auditTitle: "已採集內容",
    auditCount: "{count} 條流",
    auditEmpty: "這個時間窗沒有採集到內容。",
    auditUnavailable: "你的角色不能檢索已採集內容。",
    auditNote: "讀取正文需要審核和重新認證，所以只能在網頁管理台進行。這裡只顯示採集中介資料，從不顯示正文。",
    auditUser: "使用者 {user}",
    auditAgent: "Agent {agent}",
    auditModel: "模型 {model}",
    auditBytes: "{bytes} 位元組",
    auditClose: "關閉",
    resTitle: "企業資源",
    resEmpty: "企業還沒有發布任何資源。",
    resCount: "{count} 個資源",
    resUpdated: "更新於 {time}",
    resDelivery: "下發方式 {mode}",
    resScope: "範圍 {scope}",
    resDetail: "資源詳情",
    resReleases: "發布記錄",
    resNoReleases: "這個資源還沒有發布記錄。",
    resClose: "關閉",
    resVersion: "版本 {version}",
    resPublished: "發布於 {time}",
    syncTitle: "用戶端同步",
    syncEmpty: "還沒有裝置上報同步狀態。",
    syncCount: "{count} 台裝置",
    syncInstalled: "已安裝 {count}",
    syncDrift: "漂移 {count}",
    syncReported: "上報於 {time}",
    syncUser: "使用者 {user}",
    ovGateway: "閘道",
    ovCalls: "今日請求",
    ovRecent: "最近呼叫",
    providers: "供應商",
    providersEmpty: "閘道還沒有供應商。",
    providerAdd: "新增供應商",
    providerEdit: "編輯供應商",
    providerName: "名稱",
    providerBase: "Base URL",
    providerKey: "API Key",
    providerModels: "模型（英文逗號分隔，留空表示全部）",
    providerOff: "停用",
    save: "儲存",
    cancel: "取消",
    delete: "刪除",
    edit: "編輯",
    routing: "路由群組",
    routingEmpty: "閘道還沒有可編輯的路由群組。",
    gateway: "企業閘道",
    gatewayModels: "模型",
    gatewayKeys: "Gateway Key",
    gatewayKeysEmpty: "閘道還沒有呼叫方 Key。",
    gatewayDevices: "員工裝置",
    gatewayDevicesEmpty: "還沒有裝置加入企業。",
    deviceUser: "使用者 {user}",
    deviceLastSeen: "最後在線 {time}",
    deviceStatus: "狀態 {status}",
    keyResting: "休息中（{why}）",
    keyPrimary: "首要",
    keyWeight: "權重 {weight}",
    memberResting: "休息中（{why}）",
    providerKeyEnable: "啟用",
    providerKeyDisable: "停用",
    providerKeyPrimary: "設為首要",
    providerKeyNewValue: "貼上這個 Key 的新值。它只會傳給閘道，不會再顯示。",
    confirmRotateProviderKey: "替換 {name} 的 Key？舊值將立即失效。",
    confirmRemoveProviderKey: "刪除 Key {name}？",
    providerAddKeys: "新增 Key（每行一個）",
    keyAdd: "新增 Key",
    keyCreate: "建立",
    usage: "請求",
    usageEmpty: "還沒有記錄到請求。",
    usageRequests: "請求",
    usageSuccessful: "成功",
    usageErrors: "錯誤",
    usageTokens: "Token",
    usageCost: "費用（USD）",
    usageUsers: "按使用者",
    usageUsersCount: "{count} 個使用者",
    usageUsersEmpty: "這個時間窗沒有使用者用量。",
    usageChart: "每{bucket}請求",
    usageChartEmpty: "這個時間窗沒有用量。",
    usageUnavailable: "你的角色看不到用量彙總。",
    noData: "暫無資料",
    requestsTotal: "共 {count} 筆",
    requestRow: "{model} → {provider}",
    requestMeta: "狀態 {status} · {ms} 毫秒 · {tokens} tokens · {tries} 次嘗試",
    modelCount: "{count} 個模型",
    keyStateSet: "Key 已設定",
    keyStateMissing: "無 Key",
    keyStateSubscription: "訂閱帳號",
    badgeLive: "在線",
    badgeOff: "停用",
    confirmDeleteProvider: "刪除供應商 {name}？",
    adminUnavailable: "這台電腦尚未設定網頁管理台位址。",
    consoleAddress: "網頁管理台位址",
    consoleSave: "儲存位址",
    consoleSaved: "位址已儲存，可以登入了。",
    adminUnreachable: "無法連線網頁管理台。",
    adminExpired: "管理員工作階段已結束，請重新登入。",
    adminLoginOpened: "請在開啟的瀏覽器視窗完成登入。",
    overviewCounts: "{providers} 個供應商 · {groups} 個路由群組 · {keys} 個 Key",
    overviewUsage: "{tokens} tokens · {cost}",
    requestAccount: "帳號 {account}",
    requestKey: "Key {key}",
    requestAgent: "Agent {agent}",
    providerPreset: "預設 {preset}",
    providerPresetField: "預設（選填）",
    changeReason: "變更原因（稽核）",
    changeReasonPrompt: "為什麼要做這次變更？原因會寫入稽核記錄。",
    keyStateSetMany: "{count} 個 Key",
    routingMembers: "{count} 個成員",
    groupAdd: "新增路由群組",
    groupEdit: "編輯路由群組",
    groupId: "ID（小寫字母、數字、點、橫線）",
    groupName: "名稱",
    groupMembers: "成員（每行一個，依順序）",
    groupMatch: "符合模型（每行一個，留空表示全部）",
    groupRouting: "路由方式",
    groupAffinity: "親和性",
    groupOff: "停用成員（每行一個）",
    groupRules: "規則（JSON 陣列）",
    groupWeights: "權重（JSON 物件）",
    groupDisabled: "停用",
    invalidJson: "{field} 不是有效的 JSON。",
    confirmDeleteGroup: "刪除路由群組 {name}？",
    keyReadOnly: "唯讀",
    keyLimit: "每 {period} {tokens} tokens",
    keyEdit: "編輯 Gateway Key",
    keyPolicyNote: "修改額度或模型白名單屬於高風險操作，需在網頁管理台發起審批。",
    keyRotate: "輪換",
    keyShownOnce: "請立即儲存這個 Key，它只顯示一次：{secret}",
    keySaveNow: "請立即儲存這個 Key，它只顯示一次。",
    invalidLimit: "額度必須是非負數字。",
    approvalNeeded: "此修改需要審批。請先在網頁管理台發起審批，然後重試。",
    approvalPrompt: "網頁管理台審批中心裡的審批 ID：",
    confirmRotateKey: "輪換 {name} 的 Key？舊密鑰將立即失效。",
    confirmRemoveKey: "刪除 Key {name}？",
    routeDetail: "路由詳情",
    routeLoading: "正在讀取路由…",
    routeGone: "該路由已不在閘道記憶體中，請改看用量記錄。",
    detailRoute: "路由",
    detailTime: "時間",
    detailAgent: "Agent",
    detailModel: "模型",
    detailProvider: "供應商",
    detailStatus: "狀態",
    detailMillis: "耗時",
    detailTTFT: "首字",
    detailTokens: "輸出 tokens",
    detailGroup: "路由群組",
    detailError: "錯誤",
    detailTries: "{count} 次嘗試",
    detailSourceLive: "來源：閘道即時 trace。",
    detailSourceUsage: "來源：用量台帳（重新啟動後記憶體 trace 已不在）。",
    adminConsoleHint: "使用者、組織、裝置、審批與稽核仍在網頁管理台。",
  },
  ja: {
    adminTitle: "管理者",
    employee: "従業員",
    administrator: "管理者",
    adminGateTitle: "管理者モード",
    adminGateText: "管理アカウントでサインインし、プロバイダー・ルーティング・企業ゲートウェイを管理します。",
    adminSignIn: "サインイン",
    adminSigningIn: "ブラウザでのサインインを待っています…",
    adminSignedInAs: "{name} としてサインイン中",
    adminExpires: "セッションの有効期限 {time}",
    adminSignOut: "サインアウト",
    adminRefresh: "更新",
    webConsole: "Web コンソール",
    tabOverview: "概要",
    tabProviders: "プロバイダー",
    tabRouting: "ルーティング",
    tabGateway: "ゲートウェイ",
    tabResources: "リソース",
    tabUsage: "使用量",
    tabAudit: "監査",
    auditTitle: "収集された内容",
    auditCount: "{count} ストリーム",
    auditEmpty: "この期間に収集された内容はありません。",
    auditUnavailable: "このロールでは収集内容を検索できません。",
    auditNote: "本文の閲覧には承認と再認証が必要なため、Web コンソールで行います。このページは収集メタデータのみを表示し、本文は表示しません。",
    auditUser: "ユーザー {user}",
    auditAgent: "エージェント {agent}",
    auditModel: "モデル {model}",
    auditBytes: "{bytes} バイト",
    auditClose: "閉じる",
    resTitle: "エンタープライズリソース",
    resEmpty: "まだリソースが配布されていません。",
    resCount: "{count} 件のリソース",
    resUpdated: "{time} 更新",
    resDelivery: "配布 {mode}",
    resScope: "範囲 {scope}",
    resDetail: "リソース詳細",
    resReleases: "リリース",
    resNoReleases: "このリソースにはまだリリースがありません。",
    resClose: "閉じる",
    resVersion: "バージョン {version}",
    resPublished: "{time} 公開",
    syncTitle: "クライアント同期",
    syncEmpty: "同期状態を報告したデバイスはまだありません。",
    syncCount: "{count} 台",
    syncInstalled: "インストール済み {count}",
    syncDrift: "ドリフト {count}",
    syncReported: "{time} 報告",
    syncUser: "ユーザー {user}",
    ovGateway: "ゲートウェイ",
    ovCalls: "本日のリクエスト",
    ovRecent: "最近の呼び出し",
    providers: "プロバイダー",
    providersEmpty: "プロバイダーはまだありません。",
    providerAdd: "プロバイダーを追加",
    providerEdit: "プロバイダーを編集",
    providerName: "名前",
    providerBase: "ベース URL",
    providerKey: "API キー",
    providerModels: "モデル（カンマ区切り、空欄はすべて）",
    providerOff: "無効",
    save: "保存",
    cancel: "キャンセル",
    delete: "削除",
    edit: "編集",
    routing: "ルーティンググループ",
    routingEmpty: "編集できるルーティンググループはありません。",
    gateway: "企業ゲートウェイ",
    gatewayModels: "モデル",
    gatewayKeys: "ゲートウェイキー",
    gatewayKeysEmpty: "呼び出し元キーはまだありません。",
    gatewayDevices: "デバイス",
    gatewayDevicesEmpty: "この企業に参加したデバイスはまだありません。",
    deviceUser: "ユーザー {user}",
    deviceLastSeen: "最終確認 {time}",
    deviceStatus: "状態 {status}",
    keyResting: "休止中（{why}）",
    keyPrimary: "優先",
    keyWeight: "重み {weight}",
    memberResting: "休止中（{why}）",
    providerKeyEnable: "有効化",
    providerKeyDisable: "無効化",
    providerKeyPrimary: "優先にする",
    providerKeyNewValue: "キーの新しい値を貼り付けてください。ゲートウェイに送られ、二度と表示されません。",
    confirmRotateProviderKey: "キー {name} を置き換えますか？古い値は使えなくなります。",
    confirmRemoveProviderKey: "キー {name} を削除しますか？",
    providerAddKeys: "キーを追加（1 行に 1 つ）",
    keyAdd: "キーを追加",
    keyCreate: "作成",
    usage: "リクエスト",
    usageEmpty: "リクエストはまだ記録されていません。",
    usageRequests: "リクエスト",
    usageSuccessful: "成功",
    usageErrors: "エラー",
    usageTokens: "トークン",
    usageCost: "費用（USD）",
    usageUsers: "ユーザー別",
    usageUsersCount: "{count} 人",
    usageUsersEmpty: "この期間にユーザーの利用はありません。",
    usageChart: "{bucket}あたりのリクエスト",
    usageChartEmpty: "この期間に利用はありません。",
    usageUnavailable: "このロールでは利用集計を表示できません。",
    noData: "まだデータがありません",
    requestsTotal: "全 {count} 件",
    requestRow: "{model} → {provider}",
    requestMeta: "状態 {status} · {ms} ms · {tokens} トークン · {tries} 回試行",
    modelCount: "{count} モデル",
    keyStateSet: "キー設定済み",
    keyStateMissing: "キーなし",
    keyStateSubscription: "サブスクリプション",
    badgeLive: "稼働中",
    badgeOff: "停止",
    confirmDeleteProvider: "プロバイダー {name} を削除しますか？",
    adminUnavailable: "このコンピューターには管理コンソールのアドレスが設定されていません。",
    consoleAddress: "管理コンソールのアドレス",
    consoleSave: "アドレスを保存",
    consoleSaved: "アドレスを保存しました。サインインしてください。",
    adminUnreachable: "管理コンソールに接続できません。",
    adminExpired: "管理者セッションが終了しました。もう一度サインインしてください。",
    adminLoginOpened: "開いたブラウザーウィンドウでサインインを完了してください。",
    overviewCounts: "{providers} プロバイダー · {groups} グループ · {keys} キー",
    overviewUsage: "{tokens} トークン · {cost}",
    requestAccount: "アカウント {account}",
    requestKey: "キー {key}",
    requestAgent: "エージェント {agent}",
    providerPreset: "プリセット {preset}",
    providerPresetField: "プリセット（任意）",
    changeReason: "変更理由（監査）",
    changeReasonPrompt: "この変更の理由を入力してください。監査ログに記録されます。",
    keyStateSetMany: "{count} キー",
    routingMembers: "{count} メンバー",
    groupAdd: "ルーティンググループを追加",
    groupEdit: "ルーティンググループを編集",
    groupId: "ID（小文字・数字・ドット・ハイフン）",
    groupName: "名前",
    groupMembers: "メンバー（1 行に 1 つ、順番どおり）",
    groupMatch: "対象モデル（1 行に 1 つ、空欄はすべて）",
    groupRouting: "ルーティング",
    groupAffinity: "アフィニティ",
    groupOff: "無効にするメンバー（1 行に 1 つ）",
    groupRules: "ルール（JSON 配列）",
    groupWeights: "重み（JSON オブジェクト）",
    groupDisabled: "無効",
    invalidJson: "{field} は有効な JSON ではありません。",
    confirmDeleteGroup: "ルーティンググループ {name} を削除しますか？",
    keyReadOnly: "読み取り専用",
    keyLimit: "{period} ごとに {tokens} トークン",
    keyEdit: "ゲートウェイキーを編集",
    keyPolicyNote: "上限やモデルの許可リストの変更は高リスク操作で、Web コンソールでの承認が必要です。",
    keyRotate: "ローテーション",
    keyShownOnce: "このキーは一度しか表示されません。今すぐ保存してください: {secret}",
    keySaveNow: "このキーは一度しか表示されません。今すぐ保存してください。",
    invalidLimit: "上限は 0 以上の数値にしてください。",
    approvalNeeded: "この変更には承認が必要です。Web コンソールで承認を開始してから再試行してください。",
    approvalPrompt: "Web コンソールの承認センターにある承認 ID:",
    confirmRotateKey: "{name} のキーをローテーションしますか？古いシークレットは使えなくなります。",
    confirmRemoveKey: "キー {name} を削除しますか？",
    routeDetail: "ルート",
    routeLoading: "ルートを読み込み中…",
    routeGone: "このルートはゲートウェイのメモリにもうありません。使用量の記録を参照してください。",
    detailRoute: "ルート",
    detailTime: "時刻",
    detailAgent: "エージェント",
    detailModel: "モデル",
    detailProvider: "プロバイダー",
    detailStatus: "状態",
    detailMillis: "所要時間",
    detailTTFT: "最初のトークン",
    detailTokens: "出力トークン",
    detailGroup: "ルーティンググループ",
    detailError: "エラー",
    detailTries: "{count} 回試行",
    detailSourceLive: "ソース: ゲートウェイのライブトレース。",
    detailSourceUsage: "ソース: 使用量台帳（再起動後はトレースが残りません）。",
    adminConsoleHint: "ユーザー・組織・デバイス・承認・監査は Web コンソールにあります。",
  },
  de: {
    adminTitle: "Administrator",
    employee: "Mitarbeiter",
    administrator: "Administrator",
    adminGateTitle: "Administratormodus",
    adminGateText: "Melden Sie sich mit Ihrem Verwaltungskonto an, um Anbieter, Routing und das Unternehmensgateway zu verwalten.",
    adminSignIn: "Anmelden",
    adminSigningIn: "Warten auf den Browser…",
    adminSignedInAs: "Angemeldet als {name}",
    adminExpires: "Sitzung endet {time}",
    adminSignOut: "Abmelden",
    adminRefresh: "Aktualisieren",
    webConsole: "Webkonsole",
    tabOverview: "Übersicht",
    tabProviders: "Anbieter",
    tabRouting: "Routing",
    tabGateway: "Gateway",
    tabResources: "Ressourcen",
    tabUsage: "Nutzung",
    tabAudit: "Audit",
    auditTitle: "Erfasste Inhalte",
    auditCount: "{count} Streams",
    auditEmpty: "In diesem Zeitraum wurde kein Inhalt erfasst.",
    auditUnavailable: "Ihre Rolle darf erfasste Inhalte nicht durchsuchen.",
    auditNote: "Das Lesen eines Textes braucht eine Freigabe und eine frische Anmeldung und geschieht daher in der Webkonsole. Diese Seite zeigt nur Metadaten, nie den Text.",
    auditUser: "Benutzer {user}",
    auditAgent: "Agent {agent}",
    auditModel: "Modell {model}",
    auditBytes: "{bytes} Bytes",
    auditClose: "Schließen",
    resTitle: "Unternehmensressourcen",
    resEmpty: "Das Unternehmen hat noch keine Ressourcen veröffentlicht.",
    resCount: "{count} Ressourcen",
    resUpdated: "aktualisiert {time}",
    resDelivery: "Bereitstellung {mode}",
    resScope: "Bereich {scope}",
    resDetail: "Ressource",
    resReleases: "Veröffentlichungen",
    resNoReleases: "Diese Ressource hat noch keine Veröffentlichung.",
    resClose: "Schließen",
    resVersion: "Version {version}",
    resPublished: "veröffentlicht {time}",
    syncTitle: "Client-Synchronisierung",
    syncEmpty: "Noch kein Gerät hat seinen Synchronisierungsstatus gemeldet.",
    syncCount: "{count} Geräte",
    syncInstalled: "{count} installiert",
    syncDrift: "{count} abweichend",
    syncReported: "gemeldet {time}",
    syncUser: "Benutzer {user}",
    ovGateway: "Gateway",
    ovCalls: "Anfragen heute",
    ovRecent: "Letzte Aufrufe",
    providers: "Anbieter",
    providersEmpty: "Das Gateway hat noch keine Anbieter.",
    providerAdd: "Anbieter hinzufügen",
    providerEdit: "Anbieter bearbeiten",
    providerName: "Name",
    providerBase: "Basis-URL",
    providerKey: "API-Schlüssel",
    providerModels: "Modelle (kommagetrennt, leer für alle)",
    providerOff: "Ausgeschaltet",
    save: "Speichern",
    cancel: "Abbrechen",
    delete: "Löschen",
    edit: "Bearbeiten",
    routing: "Routinggruppen",
    routingEmpty: "Das Gateway hat keine bearbeitbaren Routinggruppen.",
    gateway: "Unternehmensgateway",
    gatewayModels: "Modelle",
    gatewayKeys: "Gateway-Schlüssel",
    gatewayKeysEmpty: "Das Gateway hat keine Aufruferschlüssel.",
    gatewayDevices: "Geräte",
    gatewayDevicesEmpty: "Diesem Unternehmen sind noch keine Geräte beigetreten.",
    deviceUser: "Benutzer {user}",
    deviceLastSeen: "zuletzt gesehen {time}",
    deviceStatus: "Status {status}",
    keyResting: "pausiert ({why})",
    keyPrimary: "primär",
    keyWeight: "Gewicht {weight}",
    memberResting: "pausiert ({why})",
    providerKeyEnable: "Aktivieren",
    providerKeyDisable: "Deaktivieren",
    providerKeyPrimary: "Primär machen",
    providerKeyNewValue: "Fügen Sie den neuen Wert des Schlüssels ein. Er geht an das Gateway und wird nie wieder angezeigt.",
    confirmRotateProviderKey: "Schlüssel {name} ersetzen? Der alte Wert wird ungültig.",
    confirmRemoveProviderKey: "Schlüssel {name} entfernen?",
    providerAddKeys: "Schlüssel hinzufügen (einer pro Zeile)",
    keyAdd: "Schlüssel hinzufügen",
    keyCreate: "Erstellen",
    usage: "Anfragen",
    usageEmpty: "Es wurden noch keine Anfragen aufgezeichnet.",
    usageRequests: "Anfragen",
    usageSuccessful: "Erfolgreich",
    usageErrors: "Fehler",
    usageTokens: "Token",
    usageCost: "Kosten (USD)",
    usageUsers: "Nach Benutzer",
    usageUsersCount: "{count} Benutzer",
    usageUsersEmpty: "In diesem Zeitraum gibt es keine Benutzernutzung.",
    usageChart: "Anfragen pro {bucket}",
    usageChartEmpty: "In diesem Zeitraum gibt es keine Nutzung.",
    usageUnavailable: "Ihre Rolle darf die Nutzungsübersicht nicht lesen.",
    noData: "Noch keine Daten",
    requestsTotal: "{count} gesamt",
    requestRow: "{model} → {provider}",
    requestMeta: "Status {status} · {ms} ms · {tokens} Token · {tries} Versuche",
    modelCount: "{count} Modelle",
    keyStateSet: "Schlüssel gesetzt",
    keyStateMissing: "Kein Schlüssel",
    keyStateSubscription: "Abo",
    badgeLive: "Aktiv",
    badgeOff: "Aus",
    confirmDeleteProvider: "Anbieter {name} löschen?",
    adminUnavailable: "Auf diesem Computer ist keine Verwaltungskonsole eingerichtet.",
    consoleAddress: "Adresse der Verwaltungskonsole",
    consoleSave: "Adresse speichern",
    consoleSaved: "Adresse gespeichert. Melden Sie sich an.",
    adminUnreachable: "Die Verwaltungskonsole ist nicht erreichbar.",
    adminExpired: "Ihre Administratorsitzung ist beendet. Melden Sie sich erneut an.",
    adminLoginOpened: "Schließen Sie die Anmeldung im geöffneten Browserfenster ab.",
    overviewCounts: "{providers} Anbieter · {groups} Gruppen · {keys} Schlüssel",
    overviewUsage: "{tokens} Token · {cost}",
    requestAccount: "Konto {account}",
    requestKey: "Schlüssel {key}",
    requestAgent: "Agent {agent}",
    providerPreset: "Voreinstellung {preset}",
    providerPresetField: "Voreinstellung (optional)",
    changeReason: "Änderungsgrund (Audit)",
    changeReasonPrompt: "Warum wird diese Änderung vorgenommen? Der Grund wird im Auditprotokoll gespeichert.",
    keyStateSetMany: "{count} Schlüssel",
    routingMembers: "{count} Mitglieder",
    groupAdd: "Routinggruppe hinzufügen",
    groupEdit: "Routinggruppe bearbeiten",
    groupId: "ID (Kleinbuchstaben, Ziffern, Punkte, Bindestriche)",
    groupName: "Name",
    groupMembers: "Mitglieder (eines pro Zeile, in Reihenfolge)",
    groupMatch: "Passende Modelle (eines pro Zeile, leer für alle)",
    groupRouting: "Routing",
    groupAffinity: "Affinität",
    groupOff: "Deaktivierte Mitglieder (eines pro Zeile)",
    groupRules: "Regeln (JSON-Array)",
    groupWeights: "Gewichte (JSON-Objekt)",
    groupDisabled: "Deaktiviert",
    invalidJson: "{field} ist kein gültiges JSON.",
    confirmDeleteGroup: "Routinggruppe {name} löschen?",
    keyReadOnly: "schreibgeschützt",
    keyLimit: "{tokens} Token pro {period}",
    keyEdit: "Gateway-Schlüssel bearbeiten",
    keyPolicyNote: "Eine Änderung an Limit oder Modellfreigabe ist risikoreich und braucht eine Genehmigung in der Webkonsole.",
    keyRotate: "Rotieren",
    keyShownOnce: "Speichern Sie diesen Schlüssel jetzt; er wird nur einmal angezeigt: {secret}",
    keySaveNow: "Speichern Sie diesen Schlüssel jetzt; er wird nur einmal angezeigt.",
    invalidLimit: "Das Limit muss eine nicht negative Zahl sein.",
    approvalNeeded: "Diese Änderung braucht eine Genehmigung. Starten Sie sie in der Webkonsole und versuchen Sie es erneut.",
    approvalPrompt: "Genehmigungs-ID aus dem Genehmigungscenter der Webkonsole:",
    confirmRotateKey: "Schlüssel für {name} rotieren? Das alte Geheimnis wird ungültig.",
    confirmRemoveKey: "Schlüssel {name} entfernen?",
    routeDetail: "Route",
    routeLoading: "Route wird geladen…",
    routeGone: "Diese Route ist nicht mehr im Speicher des Gateways. Lesen Sie stattdessen den Nutzungseintrag.",
    detailRoute: "Route",
    detailTime: "Zeit",
    detailAgent: "Agent",
    detailModel: "Modell",
    detailProvider: "Anbieter",
    detailStatus: "Status",
    detailMillis: "Dauer",
    detailTTFT: "Erstes Token",
    detailTokens: "Ausgabe-Token",
    detailGroup: "Routinggruppe",
    detailError: "Fehler",
    detailTries: "{count} Versuche",
    detailSourceLive: "Quelle: Live-Trace des Gateways.",
    detailSourceUsage: "Quelle: Nutzungsjournal (nach einem Neustart ist der Trace weg).",
    adminConsoleHint: "Benutzer, Organisationen, Geräte, Genehmigungen und Audits bleiben in der Webkonsole.",
  },
};

const adminDict = ADMIN_MESSAGES[LANG] || ADMIN_MESSAGES.en;

function ta(key, vars = {}) {
  const value = adminDict[key] ?? ADMIN_MESSAGES.en[key] ?? key;
  return value.replace(/\{([A-Za-z0-9_]+)\}/g, (_, name) => String(vars[name] ?? ""));
}

const $ = (id) => document.getElementById(id);
const syncButton = $("sync");
const noticeEl = $("notice");

let current = null;
let syncing = false;
let loading = false;
let flash = null;

function t(key, vars = {}) {
  const value = dict[key] ?? MESSAGES.en[key] ?? key;
  return value.replace(/\{([A-Za-z0-9_]+)\}/g, (_, name) => String(vars[name] ?? ""));
}

function errorText(code) {
  const value = String(code || "unknown");
  return t(`err_${value}`);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function apiUrl(path) {
  return new URL(path, location.href).href;
}

class ApiError extends Error {
  constructor(code, message, status) {
    super(message || code);
    this.code = code;
    this.status = status;
  }
}

async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(apiUrl(path), {
      cache: "no-store",
      credentials: "omit",
      ...options,
      headers: {
        "x-magpie-enterprise": TOKEN,
        ...(options.headers || {}),
      },
    });
  } catch {
    throw new ApiError("service_unreachable", t("serviceUnreachable"), 0);
  }
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    throw new ApiError(
      body?.error?.code || "http_error",
      body?.error?.message || t("requestFailed", { status: response.status }),
      response.status,
    );
  }
  return body;
}

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  try {
    return new Intl.DateTimeFormat(LOCALE, { dateStyle: "medium", timeStyle: "short" }).format(date);
  } catch {
    return date.toLocaleString();
  }
}

function formatUrl(value) {
  if (!value) return "";
  try {
    return new URL(value).origin;
  } catch {
    return value;
  }
}

function appendLines(container, lines) {
  container.replaceChildren();
  for (const line of lines.filter(Boolean)) {
    container.append(el("span", "note-line", line));
  }
}

function credentialIssue(data) {
  switch (data.credential?.state) {
    case "ok":
      return "";
    case "missing":
      return t("noCredential");
    case "unreadable":
      return t("unreadableCredential", { reason: data.credential.reason || t("unknownReason") });
    case "invalid":
      return t("invalidCredential", { reason: data.credential.reason || t("unknownReason") });
    default:
      return t("noCredential");
  }
}

function configIssue(data) {
  switch (data.syncConfig?.state) {
    case "ok":
      return "";
    case "missing":
      return t("noConfig");
    case "unreadable":
      return t("unreadableConfig", { reason: data.syncConfig.reason || t("unknownReason") });
    case "invalid":
      return t("invalidConfig", { reason: data.syncConfig.reason || t("unknownReason") });
    default:
      return t("noConfig");
  }
}

function syncIssue(data) {
  const state = data.sync?.state;
  if (state === "error") {
    const code = data.sync.lastError?.code || "unknown";
    return {
      text: code === "desired_state_unavailable"
        ? t("noticeOffline", { code: errorText(code) })
        : t("noticeSyncError", { code: errorText(code) }),
      tone: "warn",
    };
  }
  if (state === "unknown") {
    return {
      text: t("syncUnknown", { reason: data.sync.reason || t("unknownReason") }),
      tone: "warn",
    };
  }
  return null;
}

function statusNotice(data) {
  const credential = credentialIssue(data);
  if (credential) {
    return {
      text: data.credential?.state === "missing" ? t("noticeJoinFirst") : credential,
      tone: data.credential?.state === "missing" ? "warn" : "error",
    };
  }
  const config = configIssue(data);
  if (config) {
    return { text: `${config} ${t("configHint")}`, tone: "warn" };
  }
  return syncIssue(data);
}

function badge(node, text, tone) {
  node.textContent = text;
  node.className = `badge badge-${tone}`;
}

function setButton() {
  const busy = syncing || !!current?.sync?.busy;
  syncButton.disabled = busy || !current?.canSync;
  syncButton.textContent = busy ? t("syncing") : t("syncNow");
}

function renderJoined(data) {
  const ok = data.credential?.state === "ok" && data.joined;
  badge($("joinedBadge"), ok ? t("badgeJoined") : t("badgeNotJoined"), ok ? "ok" : "warn");
  $("joined").textContent = ok
    ? data.joined.email || data.joined.deviceName || data.joined.deviceId || t("joined")
    : t("notJoined");

  const lines = [];
  if (ok) {
    const device = [data.joined.deviceName, data.joined.deviceId].filter(Boolean).join(" · ");
    if (device) lines.push(device);
    if (data.joined.gatewayUrl) lines.push(t("gateway", { url: formatUrl(data.joined.gatewayUrl) }));
    if (data.joined.tokenExpiresAt) {
      lines.push(t("tokenExpires", { time: formatTime(data.joined.tokenExpiresAt) }));
    }
  } else {
    const issue = credentialIssue(data);
    lines.push(issue || t("noCredential"));
  }
  appendLines($("joinedNote"), lines);
}

function renderSync(data) {
  const state = data.sync?.state || "not_configured";
  let label = t("notConfigured");
  let tone = "muted";
  if (data.syncConfig?.state !== "ok") {
    label = t("notConfigured");
  } else if (state === "never") {
    label = t("never");
    tone = "warn";
  } else if (state === "ok") {
    label = t("synced");
    tone = "ok";
  } else if (state === "error") {
    label = t("syncError");
    tone = "warn";
  } else if (state === "unknown") {
    label = t("syncUnknown", { reason: data.sync.reason || t("unknownReason") });
    tone = "warn";
  }
  $("syncState").textContent = label;
  badge(
    $("syncBadge"),
    tone === "ok" ? t("badgeOk") : tone === "warn" ? t("badgeCheck") : t("badgeOff"),
    tone,
  );

  const lines = [];
  if (data.syncConfig?.state !== "ok") {
    lines.push(configIssue(data));
    lines.push(t("configHint"));
  } else if (state === "never") {
    lines.push(t("noRevision"));
  } else if (state === "unknown") {
    lines.push(t("syncUnknown", { reason: data.sync.reason || t("unknownReason") }));
  } else {
    if (data.sync.lastSuccessfulSyncAt) {
      lines.push(t("lastSuccess", { time: formatTime(data.sync.lastSuccessfulSyncAt) }));
    }
    if (data.sync.lastAttemptAt) {
      lines.push(t("lastAttempt", { time: formatTime(data.sync.lastAttemptAt) }));
    }
    if (data.sync.revision) {
      lines.push(t("revision", { revision: data.sync.revision }));
    } else {
      lines.push(t("noRevision"));
    }
    if (data.sync.lastError?.code) {
      lines.push(t("lastError", { code: errorText(data.sync.lastError.code) }));
    }
  }
  appendLines($("syncNote"), lines);
}

function resourceStatus(row) {
  switch (row.status) {
    case "installed":
      return { text: t("statusInstalled"), tone: "ok" };
    case "drift":
      return { text: t("statusDrift"), tone: "warn" };
    case "missing":
      return { text: t("statusMissing"), tone: "error" };
    case "disabled":
      return { text: t("statusDisabled"), tone: "muted" };
    case "orphaned":
      return { text: t("statusOrphaned"), tone: "muted" };
    default:
      return { text: row.status, tone: "muted" };
  }
}

function resourceRow(row) {
  const item = el("li", "resource");
  const main = el("div", "resource-main");
  const title = row.title ? el("strong", "resource-title", row.title) : null;
  const id = el("code", "resource-id", row.resourceId);
  const kind = row.kind || t("kindResource");
  const version = row.resourceVersion ? t("version", { version: row.resourceVersion }) : t("noVersion");
  const delivery = row.deliveryMode === "forced" ? t("deliveryForced") : t("deliveryRecommended");
  const meta = el("span", "resource-meta", `${kind} · ${version} · ${delivery}`);
  main.append(...(title ? [title, id] : [id]), meta);

  const status = resourceStatus(row);
  const pill = el("span", `status status-${status.tone}`, status.text);
  item.append(main, pill);
  return item;
}

function renderResources(data) {
  const list = $("resources");
  const empty = $("resourcesEmpty");
  list.replaceChildren();

  const rows = Array.isArray(data.resources) ? data.resources : [];
  $("resourcesCount").textContent = t("resourcesCount", { count: rows.length });
  if (rows.length > 0) {
    empty.hidden = true;
    list.append(...rows.map(resourceRow));
    return;
  }

  empty.hidden = false;
  if (data.syncConfig?.state !== "ok") empty.textContent = t("resourcesConfigMissing");
  else if (data.sync?.state === "never") empty.textContent = t("noResourcesYet");
  else empty.textContent = t("noResources");
}

function renderNotice(data) {
  let shown = null;
  if (flash && flash.until > Date.now()) shown = flash;
  else shown = statusNotice(data);
  if (!shown) {
    noticeEl.hidden = true;
    noticeEl.textContent = "";
    noticeEl.className = "notice";
    return;
  }
  noticeEl.hidden = false;
  noticeEl.textContent = shown.text;
  noticeEl.className = `notice notice-${shown.tone}`;
}

function render(data) {
  current = data;
  renderJoined(data);
  renderSync(data);
  renderResources(data);
  renderNotice(data);
  setButton();
}

async function load() {
  if (loading) return;
  loading = true;
  try {
    render(await api("v1/status"));
  } catch (error) {
    if (error instanceof ApiError && error.code === "forbidden_token") {
      noticeEl.hidden = false;
      noticeEl.className = "notice notice-error";
      noticeEl.textContent = t("pageExpired");
    } else if (error instanceof ApiError && error.code === "service_unreachable") {
      noticeEl.hidden = false;
      noticeEl.className = "notice notice-error";
      noticeEl.textContent = t("serviceUnreachable");
    } else {
      noticeEl.hidden = false;
      noticeEl.className = "notice notice-error";
      noticeEl.textContent = error?.message || t("serviceUnreachable");
    }
    setButton();
  } finally {
    loading = false;
  }
}

function syncNotice(result) {
  const code = result?.error?.code || "unknown";
  switch (result?.status) {
    case "busy":
      return { text: t("noticeBusy"), tone: "warn" };
    case "up_to_date":
      return { text: t("noticeUpToDate"), tone: "ok" };
    case "synced":
      return {
        text: t("noticeSynced", {
          installed: result.installed?.length || 0,
          unchanged: result.unchanged?.length || 0,
          skipped: result.skipped?.length || 0,
        }),
        tone: "ok",
      };
    case "offline":
      return { text: t("noticeOffline", { code: errorText(code) }), tone: "warn" };
    case "failed":
      return { text: t("noticeFailed", { code: errorText(code) }), tone: "error" };
    default:
      return { text: t("noticeFailed", { code: errorText(code) }), tone: "error" };
  }
}

async function doSync() {
  if (syncing || !current?.canSync) return;
  syncing = true;
  flash = { text: t("noticeSyncStarted"), tone: "info", until: Date.now() + 60_000 };
  render(current);
  try {
    const data = await api("v1/sync", { method: "POST" });
    const shown = syncNotice(data.result);
    if (data.result?.report?.skipped && data.result.report.reason !== "no_revision") {
      shown.text += `\n${t("noticeReportSkipped", { reason: data.result.report.reason || t("unknownReason") })}`;
    }
    flash = { ...shown, until: Date.now() + 8_000 };
    render(data);
    if (data.result?.status === "busy") setTimeout(load, 1_200);
  } catch (error) {
    const code = error instanceof ApiError ? error.code : "unknown";
    flash = {
      text: code === "forbidden_token" ? t("pageExpired") : t("noticeFailed", { code: errorText(code) }),
      tone: "error",
      until: Date.now() + 8_000,
    };
    render(current || {});
  } finally {
    syncing = false;
    setButton();
  }
}

function translate() {
  document.title = t("title");
  $("title").textContent = t("title");
  $("subtitle").textContent = t("subtitle");
  $("joinedTitle").textContent = t("device");
  $("syncTitle").textContent = t("sync");
  $("resourcesTitle").textContent = t("resources");
  syncButton.textContent = t("syncNow");
}

translate();
syncButton.addEventListener("click", doSync);
load();
setInterval(() => {
  if (!syncing && !document.hidden) load();
}, 10_000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) load();
});

// ---------------------------------------------------------------------
// Administrator mode
//
// The page only talks to this computer's enterprise service. The
// administrator's token, the gateway's token and every provider key stay
// on the service side; what comes back here is a projection.

let adminState = null;
let adminTab = "overview";
let adminBusy = false;
let editingProvider = null;
let editingGroup = null;
let editingKey = null;
let selectedRoute = null;

class AdminApiError extends Error {
  constructor(code, message, status) {
    super(message || code);
    this.code = code;
    this.status = status;
  }
}

async function adminApi(path, { method = "GET", body } = {}) {
  let response;
  try {
    response = await fetch(apiUrl(`v1/admin${path}`), {
      method,
      cache: "no-store",
      credentials: "omit",
      headers: {
        "x-magpie-enterprise": TOKEN,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new AdminApiError("service_unreachable", ta("adminUnreachable"), 0);
  }
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    throw new AdminApiError(
      payload?.error?.code || "http_error",
      payload?.error?.message || ta("adminUnreachable"),
      response.status,
    );
  }
  return payload;
}

function adminNotice(text, tone) {
  noticeEl.hidden = false;
  noticeEl.textContent = text;
  noticeEl.className = `notice notice-${tone}`;
}

function setView(name) {
  const admin = name === "admin";
  $("viewEmployee").classList.toggle("is-on", !admin);
  $("viewEmployee").setAttribute("aria-selected", String(!admin));
  $("viewAdmin").classList.toggle("is-on", admin);
  $("viewAdmin").setAttribute("aria-selected", String(admin));
  $("employeeView").hidden = admin;
  $("adminView").hidden = !admin;
  syncButton.hidden = admin;
  $("signIn").hidden = true;
  $("title").textContent = admin ? ta("adminTitle") : t("title");
  $("subtitle").textContent = admin ? ta("adminConsoleHint") : t("subtitle");
  if (admin) loadAdmin();
  else load();
}

async function loadAdmin() {
  try {
    adminState = await adminApi("/status");
  } catch (error) {
    adminState = { configured: false, signedIn: false };
    adminNotice(error.message || ta("adminUnreachable"), "error");
  }
  renderAdmin();
}

function renderAdmin() {
  const state = adminState || { configured: false, signedIn: false };
  const signedIn = Boolean(state.signedIn);
  $("adminSignedOut").hidden = signedIn;
  $("adminSignedIn").hidden = !signedIn;
  $("adminGateText").textContent = state.configured
    ? ta("adminGateText")
    : ta("adminUnavailable");
  // With no address the page asks for one instead of sending the
  // administrator off to edit a file they have no reason to know about.
  $("consoleForm").hidden = Boolean(state.configured);
  $("adminSignIn").disabled = !state.configured || adminBusy;
  $("adminGateTitle").textContent = ta("adminGateTitle");
  $("openConsole").hidden = !state.configured;
  if (!state.configured) return;

  const consoleUrl = new URL("/admin/", state.adminUrl).toString();
  $("openConsole").onclick = () => window.open(consoleUrl, "_blank", "noopener,noreferrer");
  $("openConsoleSignedIn").href = consoleUrl;

  if (!signedIn) return;
  const who = state.user?.email || state.user?.name || "";
  $("adminWho").textContent = ta("adminSignedInAs", { name: who });
  const expires = state.expiresAt ? ta("adminExpires", { time: formatTime(state.expiresAt) }) : "";
  $("adminWho").title = expires;
  loadAdminTab();
}

async function saveConsole(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const value = form.elements.adminUrl.value.trim();
  try {
    adminState = await adminApi("/console", {
      method: "PUT",
      body: { adminUrl: value },
    });
    $("consoleNote").textContent = ta("consoleSaved");
    renderAdmin();
  } catch (error) {
    $("consoleNote").textContent = error.message || ta("adminUnreachable");
  }
}

// The resource catalog and each device's last sync report, read-only.
// Publishing and rollback stay in the management service until their
// approval path can be driven from this page.
async function loadResources() {
  let catalog = { resources: [] };
  let reports = { reports: [] };
  try {
    catalog = await adminApi("/resources");
  } catch (error) {
    // A role may read devices without the resource catalog, or the
    // reverse. Each list answers on its own; the other stays empty.
    if (!(error instanceof AdminApiError) || error.status !== 403) throw error;
  }
  try {
    reports = await adminApi("/resource-sync/reports");
  } catch (error) {
    if (!(error instanceof AdminApiError) || error.status !== 403) throw error;
  }
  renderAdminResources(catalog.resources || [], reports.reports || []);
}

function renderAdminResources(resources, reports) {
  $("resDetail").hidden = true;
  $("resCount").textContent = ta("resCount", { count: resources.length });
  $("resList").replaceChildren(...resources.map(catalogResourceRow));
  $("resEmpty").hidden = resources.length > 0;
  $("resEmpty").textContent = ta("resEmpty");
  $("syncCount").textContent = ta("syncCount", { count: reports.length });
  $("syncList").replaceChildren(...reports.map(syncReportRow));
  $("syncEmpty").hidden = reports.length > 0;
  $("syncEmpty").textContent = ta("syncEmpty");
}

function catalogResourceRow(resource) {
  const item = el("article", "resource resource-link");
  const main = el("div", "resource-main");
  main.append(el("span", "resource-title", resource.name || resource.id));
  main.append(el("span", "resource-id", resource.id));
  main.append(el("span", "resource-meta", [
    resource.kind,
    resource.deliveryMode ? ta("resDelivery", { mode: resource.deliveryMode }) : "",
    resource.updatedAt ? ta("resUpdated", { time: formatTime(resource.updatedAt) }) : "",
    (resource.assignments || []).length
      ? ta("resScope", { scope: resource.assignments.join(", ") })
      : "",
  ].filter(Boolean).join(" · ")));
  const tone = resource.status === "active" ? "ok" : "muted";
  item.append(main, el("span", `status status-${tone}`, resource.status || resource.kind || ""));
  item.addEventListener("click", () => openResource(resource));
  return item;
}

// A resource's detail is its current release and its release history; the
// content itself is not shown here, only its version, hash and time.
async function openResource(resource) {
  const panel = $("resDetail");
  panel.hidden = false;
  $("resDetailTitle").textContent = resource.name || resource.id;
  $("resDetailClose").textContent = ta("resClose");
  $("resReleasesTitle").textContent = ta("resReleases");
  $("resDetailBody").replaceChildren(
    detailLine(resource.kind || "", resource.id),
    detailLine(
      resource.deliveryMode ? ta("resDelivery", { mode: resource.deliveryMode }) : "",
      (resource.assignments || []).join(", ") || "*",
    ),
    detailLine(
      resource.status || "",
      resource.updatedAt ? ta("resUpdated", { time: formatTime(resource.updatedAt) }) : "",
    ),
  );
  $("resReleases").replaceChildren();
  $("resReleasesEmpty").hidden = true;
  try {
    const payload = await adminApi(`/resources/${encodeURIComponent(resource.id)}`);
    const releases = Array.isArray(payload.releases) ? payload.releases : [];
    $("resReleases").replaceChildren(...releases.map(releaseRow));
    $("resReleasesEmpty").hidden = releases.length > 0;
    $("resReleasesEmpty").textContent = ta("resNoReleases");
  } catch (error) {
    $("resReleasesEmpty").hidden = false;
    $("resReleasesEmpty").textContent = error.message || ta("adminUnreachable");
  }
}

function detailLine(label, value) {
  const line = el("div", "detail-line");
  if (label) line.append(el("b", "", label));
  if (value) line.append(el("span", "", value));
  return line;
}

function releaseRow(release) {
  const item = el("article", "resource");
  const main = el("div", "resource-main");
  main.append(el(
    "span",
    "resource-title",
    ta("resVersion", { version: release.resourceVersion || release.id }),
  ));
  main.append(el("span", "resource-meta", [
    release.status,
    release.hash ? String(release.hash).slice(0, 12) : "",
    release.publishedAt || release.createdAt
      ? ta("resPublished", { time: formatTime(release.publishedAt || release.createdAt) })
      : "",
  ].filter(Boolean).join(" · ")));
  item.append(main);
  return item;
}

function syncReportRow(report) {
  const item = el("article", "resource");
  const main = el("div", "resource-main");
  main.append(el("span", "resource-title", report.deviceId || ""));
  main.append(el("span", "resource-id", report.userId ? ta("syncUser", { user: report.userId }) : ""));
  main.append(el("span", "resource-meta", [
    report.status,
    ta("syncInstalled", { count: (report.installed || []).length }),
    ta("syncDrift", { count: report.driftCount || 0 }),
    report.reportedAt ? ta("syncReported", { time: formatTime(report.reportedAt) }) : "",
  ].filter(Boolean).join(" · ")));
  const tone = (report.driftCount || 0) > 0 ? "danger" : "ok";
  item.append(main, el("span", `status status-${tone}`, report.status || ""));
  return item;
}

function selectTab(name) {
  adminTab = name;
  for (const button of document.querySelectorAll("#adminTabs .tab")) {
    const on = button.dataset.tab === name;
    button.classList.toggle("is-on", on);
    button.setAttribute("aria-selected", String(on));
    button.tabIndex = on ? 0 : -1;
  }
  for (const panel of document.querySelectorAll(".tab-panel")) {
    panel.hidden = panel.dataset.panel !== name;
  }
  loadAdminTab();
}

async function loadAdminTab() {
  if (!adminState?.signedIn) return;
  try {
    switch (adminTab) {
      case "overview":
        return renderOverview(await adminApi("/overview"));
      case "providers":
        return renderProviders(await adminApi("/providers"));
      case "routing":
        return renderRouting(await adminApi("/routing-groups"));
      case "gateway":
        {
          const data = await adminApi("/gateway");
          let devices = [];
          try {
            devices = (await adminApi("/devices")).devices || [];
          } catch (error) {
            // A role may read the gateway without reading devices. The
            // rest of the page still answers; only the device list is
            // empty, and the console remains the place to grant it.
            if (!(error instanceof AdminApiError) || error.status !== 403) throw error;
          }
          return renderGateway({ ...data, devices });
        }
      case "resources":
        return loadResources();
      case "usage":
        return loadUsage();
      case "audit":
        return loadAudit();
      default:
        return undefined;
    }
  } catch (error) {
    if (error instanceof AdminApiError && error.status === 401) {
      adminState = { ...adminState, signedIn: false };
      renderAdmin();
      adminNotice(ta("adminExpired"), "warn");
      return undefined;
    }
    adminNotice(error.message || ta("adminUnreachable"), "error");
    return undefined;
  }
}

function renderOverview(data) {
  const gateway = data.gateway || {};
  const counts = data.counts || {};
  badge($("ovGatewayBadge"), gateway.ok ? ta("badgeLive") : ta("badgeOff"), gateway.ok ? "ok" : "muted");
  $("ovGateway").textContent = gateway.version
    ? `${gateway.version} · ${gateway.address || ""}`
    : ta("noData");
  appendLines($("ovGatewayNote"), [
    gateway.publicURL ? gateway.publicURL : "",
    ta("modelCount", { count: (gateway.models || []).length }),
  ]);
  badge($("ovCallsBadge"), String(counts.failures || 0), counts.failures ? "warn" : "ok");
  $("ovCalls").textContent = Number.isFinite(counts.requests) ? String(counts.requests) : ta("noData");
  appendLines($("ovCallsNote"), [
    ta("overviewCounts", {
      providers: counts.providers || 0,
      groups: counts.groups || 0,
      keys: counts.keys || 0,
    }),
    ta("overviewUsage", {
      tokens: formatNumber(counts.tokens || 0),
      cost: formatCost(counts.cost || 0),
    }),
  ]);
  renderRequests($("ovRecent"), $("ovRecentEmpty"), $("ovRecentCount"), data.recent || []);
}

function formatNumber(value) {
  return new Intl.NumberFormat(LOCALE).format(Number(value) || 0);
}

function formatCost(value) {
  return `$${(Number(value) || 0).toFixed(4)}`;
}

function renderRequests(list, empty, count, rows) {
  list.replaceChildren();
  count.textContent = ta("requestsTotal", { count: rows.length });
  if (rows.length === 0) {
    empty.hidden = false;
    empty.textContent = ta("usageEmpty");
    return;
  }
  empty.hidden = true;
  list.append(...rows.map(requestRow));
}

function requestRow(row) {
  const item = el("li", "resource");
  const main = el("div", "resource-main");
  main.append(
    el("strong", "resource-title", ta("requestRow", {
      model: row.requested || row.model || "?",
      provider: row.provider || "?",
    })),
    el("span", "resource-meta", ta("requestMeta", {
      status: row.status || 0,
      ms: row.millis || 0,
      tokens: row.tokens || 0,
      tries: row.tries || 0,
    })),
  );
  const facts = [
    row.time ? formatTime(row.time) : "",
    row.account ? ta("requestAccount", { account: row.account }) : "",
    row.callerKeyName ? ta("requestKey", { key: row.callerKeyName }) : "",
    row.agent ? ta("requestAgent", { agent: row.agent }) : "",
  ].filter(Boolean);
  if (facts.length) main.append(el("span", "resource-meta", facts.join(" · ")));
  if (row.error) main.append(el("span", "resource-meta", row.error));
  const tone = row.status >= 400 ? "error" : row.status >= 300 ? "warn" : "ok";
  item.append(main, el("span", `status status-${tone}`, String(row.status || "")));
  if (row.routeId) {
    item.classList.add("resource-link");
    item.tabIndex = 0;
    item.setAttribute("role", "button");
    const open = () => loadRouteDetail(row.routeId);
    item.addEventListener("click", open);
    item.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        open();
      }
    });
  }
  return item;
}

function renderProviders(data) {
  const rows = Array.isArray(data.providers) ? data.providers : [];
  const list = $("providersList");
  list.replaceChildren();
  $("providersCount").textContent = String(rows.length);
  $("providersEmpty").hidden = rows.length > 0;
  $("providersEmpty").textContent = ta("providersEmpty");
  list.append(...rows.map(providerRow));
}

function providerRow(provider) {
  const item = el("li", "resource resource-actions");
  const main = el("div", "resource-main");
  const keys = Array.isArray(provider.keys) ? provider.keys : [];
  const keyLine = keys.length > 0
    ? keys.map((key) => providerKeyLine(key)).join(" · ")
    : providerKeyState(provider);
  main.append(
    el("strong", "resource-title", provider.name || provider.id),
    el("code", "resource-id", provider.id),
    el("span", "resource-meta", [
      provider.host || provider.chat || "",
      ta("modelCount", { count: provider.modelCount || 0 }),
      providerKeyState(provider),
      provider.preset ? ta("providerPreset", { preset: provider.preset }) : "",
    ].filter(Boolean).join(" · ")),
    ...(keyLine ? [el("span", "resource-meta", keyLine)] : []),
  );
  if (keys.length > 0) {
    const keyList = el("ul", "key-list");
    for (const key of keys) keyList.append(providerKeyRow(provider, key));
    main.append(keyList);
  }
  const actions = el("div", "row-actions");
  const edit = el("button", "linkish", ta("edit"));
  const remove = el("button", "linkish", ta("delete"));
  actions.append(edit, remove);
  const state = el("span", `status status-${provider.off ? "muted" : provider.ready ? "ok" : "warn"}`,
    provider.off ? ta("badgeOff") : provider.ready ? ta("badgeLive") : ta("keyStateMissing"));
  edit.addEventListener("click", () => openProviderForm(provider));
  remove.addEventListener("click", () => deleteProvider(provider));
  item.append(main, state, actions);
  return item;
}

// providerKeyRow gives each key its own controls. A key is named by its
// fingerprint; its value is only ever written, from the rotate prompt.
function providerKeyRow(provider, key) {
  const item = el("li", "key-row");
  item.append(el("span", "key-line", providerKeyLine(key)));
  const actions = el("div", "row-actions");
  const toggle = el("button", "linkish", key.on ? ta("providerKeyDisable") : ta("providerKeyEnable"));
  const primary = el("button", "linkish", ta("providerKeyPrimary"));
  const rotate = el("button", "linkish", ta("keyRotate"));
  const remove = el("button", "linkish", ta("delete"));
  primary.disabled = key.active;
  toggle.addEventListener("click", () => patchProviderKey(provider, {
    id: key.id,
    on: !key.on,
  }));
  primary.addEventListener("click", () => patchProviderKey(provider, {
    id: key.id,
    use: true,
  }));
  rotate.addEventListener("click", () => {
    if (!window.confirm(ta("confirmRotateProviderKey", { name: key.name || key.masked }))) return;
    const value = window.prompt(ta("providerKeyNewValue"), "");
    if (!value) return;
    patchProviderKey(provider, { id: key.id, key: value });
  });
  remove.addEventListener("click", () => {
    if (!window.confirm(ta("confirmRemoveProviderKey", { name: key.name || key.masked }))) return;
    patchProviderKey(provider, { id: key.id, remove: true });
  });
  actions.append(toggle, primary, rotate, remove);
  item.append(actions);
  return item;
}

async function patchProviderKey(provider, change) {
  const reason = window.prompt(ta("changeReasonPrompt"), "");
  if (!reason) return;
  try {
    await adminApi(`/providers/${encodeURIComponent(provider.id)}`, {
      method: "PATCH",
      body: {
        expectedRevision: provider.revision,
        reason,
        keys: [change],
      },
    });
    await loadAdminTab();
  } catch (error) {
    adminNotice(error.message || ta("adminUnreachable"), "error");
  }
}

// providerKeyLine says one key's name and state, never its value.
function providerKeyLine(key) {
  const state = key.rest
    ? ta("keyResting", { why: key.rest.why || key.rest.status || "" })
    : key.on ? ta("badgeLive") : ta("badgeOff");
  const settings = [
    key.name || key.masked,
    key.active ? ta("keyPrimary") : "",
    key.protocol || "",
    key.weight > 1 ? ta("keyWeight", { weight: key.weight }) : "",
    key.plan || "",
    state,
  ].filter(Boolean);
  return settings.join(" · ");
}

function providerKeyState(provider) {
  if (provider.keyState === "subscription") return ta("keyStateSubscription");
  if (provider.keyState === "set") {
    return provider.keyCount > 1
      ? ta("keyStateSetMany", { count: provider.keyCount })
      : ta("keyStateSet");
  }
  return ta("keyStateMissing");
}

function openProviderForm(provider) {
  editingProvider = provider || null;
  const form = $("providerForm");
  form.hidden = false;
  $("providerFormTitle").textContent = provider ? ta("providerEdit") : ta("providerAdd");
  form.elements.name.value = provider?.name || "";
  form.elements.preset.value = provider?.preset || "";
  form.elements.baseAPI.value = provider?.chat || provider?.baseAPI || "";
  form.elements.key.value = "";
  form.elements.addKeys.value = "";
  form.elements.models.value = (provider?.models || []).join(", ");
  form.elements.off.checked = Boolean(provider?.off);
  form.elements.name.focus();
}

async function saveProvider(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const models = form.elements.models.value
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const body = {
    name: form.elements.name.value.trim(),
    preset: form.elements.preset.value.trim(),
    models,
    off: form.elements.off.checked,
    reason: form.elements.reason.value.trim(),
  };
  const addKeys = splitLines(form.elements.addKeys.value);
  if (addKeys.length > 0) body.addKeys = addKeys;
  const base = form.elements.baseAPI.value.trim();
  if (base) {
    body.chat = base;
    body.baseAPI = "chat";
  }
  if (form.elements.key.value) body.key = form.elements.key.value;
  try {
    adminBusy = true;
    if (editingProvider) {
      await adminApi(`/providers/${encodeURIComponent(editingProvider.id)}`, {
        method: "PATCH",
        body: { ...body, expectedRevision: editingProvider.revision },
      });
    } else {
      await adminApi("/providers", { method: "POST", body });
    }
    form.hidden = true;
    editingProvider = null;
    await loadAdminTab();
  } catch (error) {
    adminNotice(error.message || ta("adminUnreachable"), "error");
  } finally {
    adminBusy = false;
  }
}

async function deleteProvider(provider) {
  if (!window.confirm(ta("confirmDeleteProvider", { name: provider.name || provider.id }))) return;
  const reason = window.prompt(ta("changeReasonPrompt"), "");
  if (!reason) return;
  try {
    await adminApi(`/providers/${encodeURIComponent(provider.id)}`, {
      method: "DELETE",
      body: { expectedRevision: provider.revision, reason },
    });
    await loadAdminTab();
  } catch (error) {
    adminNotice(error.message || ta("adminUnreachable"), "error");
  }
}

function renderRouting(data) {
  const rows = Array.isArray(data.groups) ? data.groups : [];
  const list = $("routingList");
  list.replaceChildren();
  $("routingCount").textContent = String(rows.length);
  $("routingEmpty").hidden = rows.length > 0;
  $("routingEmpty").textContent = ta("routingEmpty");
  list.append(...rows.map((group) => {
    const item = el("li", "resource resource-actions");
    const main = el("div", "resource-main");
    const live = Array.isArray(group.live) ? group.live : [];
    main.append(
      el("strong", "resource-title", group.name || group.id),
      el("code", "resource-id", group.id),
      el("span", "resource-meta", [
        ta("routingMembers", { count: group.members?.length || 0 }),
        group.routing || "smart",
        group.affinity || "",
        group.disabled ? ta("badgeOff") : "",
      ].filter(Boolean).join(" · ")),
      el("span", "resource-meta", (group.members || []).join(" → ")),
      ...(live.length > 0
        ? [el("span", "resource-meta", live.map((member) => groupMemberLine(member)).join(" · "))]
        : []),
    );
    const actions = el("div", "row-actions");
    const edit = el("button", "linkish", ta("edit"));
    const remove = el("button", "linkish", ta("delete"));
    edit.addEventListener("click", () => openGroupForm(group));
    remove.addEventListener("click", () => deleteGroup(group));
    actions.append(edit, remove);
    item.append(
      main,
      el("span", `status status-${group.disabled ? "muted" : "ok"}`,
        group.disabled ? ta("badgeOff") : ta("badgeLive")),
      actions,
    );
    return item;
  }));
}

// groupMemberLine says whether a member is used now, and why it rests.
function groupMemberLine(member) {
  const label = member.id || `${member.provider}/${member.model}`;
  const state = member.rest
    ? ta("memberResting", { why: member.rest.why || member.rest.status || "" })
    : member.on ? ta("badgeLive") : ta("badgeOff");
  return `${label} ${state}`;
}

function splitLines(value) {
  return String(value || "")
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function openGroupForm(group) {
  editingGroup = group || null;
  const form = $("groupForm");
  form.hidden = false;
  $("groupFormTitle").textContent = group ? ta("groupEdit") : ta("groupAdd");
  form.elements.id.value = group?.id || "";
  form.elements.id.disabled = Boolean(group);
  form.elements.name.value = group?.name || "";
  form.elements.members.value = (group?.members || []).join("\n");
  form.elements.match.value = (group?.match || []).join("\n");
  form.elements.routing.value = group?.routing || "";
  form.elements.affinity.value = group?.affinity || "";
  form.elements.off.value = (group?.off || []).join("\n");
  form.elements.rules.value = group?.rules?.length ? JSON.stringify(group.rules, null, 2) : "";
  form.elements.weights.value = group?.weights && Object.keys(group.weights).length
    ? JSON.stringify(group.weights, null, 2)
    : "";
  form.elements.disabled.checked = Boolean(group?.disabled);
  form.elements.id.focus();
}

function parseJsonField(value, kind, fieldName) {
  const text = String(value || "").trim();
  if (!text) return undefined;
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new AdminApiError("invalid_json", ta("invalidJson", { field: ta(fieldName) }));
  }
  if (kind === "array" && !Array.isArray(parsed)) {
    throw new AdminApiError("invalid_json", ta("invalidJson", { field: ta(fieldName) }));
  }
  if (kind === "object"
      && (Array.isArray(parsed) || !parsed || typeof parsed !== "object")) {
    throw new AdminApiError("invalid_json", ta("invalidJson", { field: ta(fieldName) }));
  }
  return parsed;
}

async function saveGroup(event) {
  event.preventDefault();
  if (adminBusy) return;
  const form = event.currentTarget;
  const body = {
    name: form.elements.name.value.trim(),
    members: splitLines(form.elements.members.value),
    match: splitLines(form.elements.match.value),
    routing: form.elements.routing.value.trim(),
    affinity: form.elements.affinity.value.trim(),
    off: splitLines(form.elements.off.value),
    disabled: form.elements.disabled.checked,
    reason: form.elements.reason.value.trim(),
  };
  try {
    const rules = parseJsonField(form.elements.rules.value, "array", "groupRules");
    const weights = parseJsonField(form.elements.weights.value, "object", "groupWeights");
    if (rules !== undefined) body.rules = rules;
    if (weights !== undefined) body.weights = weights;
    adminBusy = true;
    if (editingGroup) {
      await adminApi(`/routing-groups/${encodeURIComponent(editingGroup.id)}`, {
        method: "PATCH",
        body: { ...body, expectedRevision: editingGroup.revision },
      });
    } else {
      await adminApi("/routing-groups", {
        method: "POST",
        body: { ...body, id: form.elements.id.value.trim().toLowerCase() },
      });
    }
    form.hidden = true;
    editingGroup = null;
    await loadAdminTab();
  } catch (error) {
    adminNotice(error.message || ta("adminUnreachable"), "error");
  } finally {
    adminBusy = false;
  }
}

async function deleteGroup(group) {
  if (!window.confirm(ta("confirmDeleteGroup", { name: group.name || group.id }))) return;
  const reason = window.prompt(ta("changeReasonPrompt"), "");
  if (!reason) return;
  try {
    await adminApi(`/routing-groups/${encodeURIComponent(group.id)}`, {
      method: "DELETE",
      body: { expectedRevision: group.revision, reason },
    });
    await loadAdminTab();
  } catch (error) {
    adminNotice(error.message || ta("adminUnreachable"), "error");
  }
}

function renderGateway(data) {
  const gateway = data.gateway || {};
  const keys = Array.isArray(data.keys) ? data.keys : [];
  badge($("gwBadge"), gateway.ok ? ta("badgeLive") : ta("badgeOff"), gateway.ok ? "ok" : "muted");
  $("gwAddress").textContent = gateway.publicURL || gateway.address || ta("noData");
  appendLines($("gwNote"), [
    gateway.version || "",
    gateway.startedAt ? formatTime(gateway.startedAt) : "",
  ]);
  $("gwModelsCount").textContent = String((gateway.models || []).length);
  $("gwModels").textContent = (gateway.models || []).join(", ") || ta("noData");
  $("gwKeysCount").textContent = String(keys.length);
  $("gwKeysEmpty").hidden = keys.length > 0;
  $("gwKeysEmpty").textContent = ta("gatewayKeysEmpty");
  const list = $("gwKeys");
  list.replaceChildren(...keys.map((key) => {
    const item = el("li", "resource resource-actions");
    const main = el("div", "resource-main");
    const limit = key.limit
      ? ta("keyLimit", {
        period: key.limit.period || "day",
        tokens: formatNumber(key.limit.tokens || 0),
      })
      : "";
    main.append(
      el("strong", "resource-title", key.name || key.id),
      el("code", "resource-id", key.masked || key.id),
      el("span", "resource-meta", [
        key.state,
        (key.models || []).length ? ta("modelCount", { count: key.models.length }) : "",
        key.readOnly ? ta("keyReadOnly") : "",
        limit,
        key.expiresAt ? formatTime(key.expiresAt) : "",
      ].filter(Boolean).join(" · ")),
    );
    const actions = el("div", "row-actions");
    const edit = el("button", "linkish", ta("edit"));
    const rotate = el("button", "linkish", ta("keyRotate"));
    const remove = el("button", "linkish", ta("delete"));
    edit.addEventListener("click", () => openKeyForm(key));
    rotate.addEventListener("click", () => rotateKey(key));
    remove.addEventListener("click", () => removeKey(key));
    actions.append(edit, rotate, remove);
    item.append(
      main,
      el("span", `status status-${key.state === "enabled" ? "ok" : "muted"}`, key.state),
      actions,
    );
    return item;
  }));

  // The employees' devices are a read-only window here: revoking one stays
  // in the web console, where the approval and audit live.
  const devices = Array.isArray(data.devices) ? data.devices : [];
  $("gwDevicesCount").textContent = String(devices.length);
  $("gwDevicesEmpty").hidden = devices.length > 0;
  $("gwDevicesEmpty").textContent = ta("gatewayDevicesEmpty");
  $("gwDevices").replaceChildren(...devices.map(deviceRow));
}

// deviceRow shows a device's identity and last contact, never a token.
function deviceRow(device) {
  const item = el("li", "resource");
  const main = el("div", "resource-main");
  const meta = [
    device.platform || "",
    device.clientVersion || "",
    device.userId ? ta("deviceUser", { user: device.userId }) : "",
    device.lastSeenAt ? ta("deviceLastSeen", { time: formatTime(device.lastSeenAt) }) : "",
  ].filter(Boolean);
  main.append(
    el("strong", "resource-title", device.name || device.id || "?"),
    el("code", "resource-id", device.id || ""),
    el("span", "resource-meta", meta.join(" · ")),
  );
  const state = String(device.status || "unknown");
  const tone = state === "active" ? "ok" : state === "revoked" ? "error" : "muted";
  item.append(
    main,
    el("span", `status status-${tone}`, ta("deviceStatus", { status: state })),
  );
  return item;
}

// Collected content, metadata only. Reading a body needs an approval, CSRF
// and a fresh step-up, which the web console drives; this page must never
// offer a read it cannot authorize.
async function loadAudit() {
  const form = $("auditFilter");
  const params = new URLSearchParams();
  for (const name of ["userId", "agentId", "modelId", "status"]) {
    const value = String(form.elements[name]?.value || "").trim();
    if (value) params.set(name, value);
  }
  params.set("limit", "50");
  $("auditDetail").hidden = true;
  try {
    const payload = await adminApi(`/audit/streams?${params}`);
    renderAudit(Array.isArray(payload.streams) ? payload.streams : []);
  } catch (error) {
    if (error instanceof AdminApiError && error.status === 403) {
      renderAudit([]);
      $("auditEmpty").hidden = false;
      $("auditEmpty").textContent = ta("auditUnavailable");
      return;
    }
    throw error;
  }
}

function renderAudit(streams) {
  $("auditCount").textContent = ta("auditCount", { count: streams.length });
  $("auditList").replaceChildren(...streams.map(auditRow));
  $("auditEmpty").hidden = streams.length > 0;
  $("auditEmpty").textContent = ta("auditEmpty");
}

function auditRow(stream) {
  const item = el("article", "resource resource-link");
  const main = el("div", "resource-main");
  main.append(el("span", "resource-title", stream.contentKind || stream.streamId || ""));
  main.append(el("span", "resource-meta", [
    stream.status,
    stream.userId ? ta("auditUser", { user: stream.userId }) : "",
    stream.agentId ? ta("auditAgent", { agent: stream.agentId }) : "",
    stream.modelId ? ta("auditModel", { model: stream.modelId }) : "",
    Number.isFinite(Number(stream.bytes))
      ? ta("auditBytes", { bytes: Number(stream.bytes) })
      : "",
    stream.createdAt ? formatTime(stream.createdAt) : "",
  ].filter(Boolean).join(" · ")));
  const tone = stream.status === "finalized" ? "ok"
    : stream.status === "failed" ? "danger" : "muted";
  item.append(main, el("span", `status status-${tone}`, stream.status || ""));
  item.addEventListener("click", () => openAuditStream(stream.streamId));
  return item;
}

async function openAuditStream(streamId) {
  const panel = $("auditDetail");
  panel.hidden = false;
  $("auditDetailTitle").textContent = streamId || "";
  $("auditDetailClose").textContent = ta("auditClose");
  const body = $("auditDetailBody");
  body.replaceChildren(el("p", "detail-line", ta("auditNote")));
  try {
    const payload = await adminApi(`/audit/streams/${encodeURIComponent(streamId)}`);
    const stream = payload.stream || {};
    body.replaceChildren(
      detailLine("request", stream.requestId || ""),
      detailLine(ta("auditUser", { user: stream.userId || "" }), stream.departmentId || ""),
      detailLine(ta("auditAgent", { agent: stream.agentId || "" }), stream.modelId || ""),
      detailLine(stream.auditLevel || "", stream.contentKind || ""),
      detailLine(stream.auditLevel === "L2" ? ta("auditBytes", { bytes: stream.bytes || 0 }) : "",
        stream.finalizedAt ? formatTime(stream.finalizedAt) : ""),
      detailLine(stream.contentRetentionExpiresAt
        ? `retention ${formatTime(stream.contentRetentionExpiresAt)}` : "",
      stream.contentRef || ""),
    );
  } catch (error) {
    body.replaceChildren(el("p", "detail-line", error.message || ta("adminUnreachable")));
  }
}

// Org-wide usage: the totals, one row per user and a bar per bucket, above
// the request list. The summary is scoped by the management service to the
// administrator's organization; a role without usage.read still sees the
// request list, so each part answers on its own.
async function loadUsage() {
  const query = "period=week";
  let summary = null;
  let series = null;
  try {
    summary = await adminApi(`/usage/summary?${query}`);
  } catch (error) {
    if (!(error instanceof AdminApiError) || error.status !== 403) throw error;
  }
  try {
    series = await adminApi(`/usage/timeseries?${query}&bucket=day&groupBy=all`);
  } catch (error) {
    if (!(error instanceof AdminApiError) || error.status !== 403) throw error;
  }
  renderUsageSummary(summary);
  renderUsageUsers(summary);
  renderUsageChart(series);
  renderUsage(await adminApi("/requests?period=week&limit=100"));
}

function usageCard(label, value) {
  const card = el("article", "card");
  card.append(el("h3", "", label), el("p", "value", String(value ?? 0)));
  return card;
}

function renderUsageSummary(summary) {
  const target = $("usageCards");
  if (!summary) {
    target.replaceChildren();
    $("usageNote").textContent = ta("usageUnavailable");
    return;
  }
  $("usageNote").textContent = "";
  const totals = summary.totals || {};
  target.replaceChildren(
    usageCard(ta("usageRequests"), totals.requests || 0),
    usageCard(ta("usageSuccessful"), totals.successfulRequests || 0),
    usageCard(ta("usageErrors"), totals.errors || 0),
    usageCard(ta("usageTokens"), totals.totalTokens || 0),
    usageCard(ta("usageCost"), Number(totals.costUsd || 0).toFixed(4)),
  );
}

function renderUsageUsers(summary) {
  const rows = Array.isArray(summary?.dimensions?.user) ? summary.dimensions.user : [];
  $("usageUsersCount").textContent = ta("usageUsersCount", { count: rows.length });
  $("usageUsers").replaceChildren(...rows.map(usageUserRow));
  $("usageUsersEmpty").hidden = rows.length > 0;
  $("usageUsersEmpty").textContent = ta("usageUsersEmpty");
}

function usageUserRow(row) {
  const item = el("article", "resource");
  const main = el("div", "resource-main");
  main.append(el("span", "resource-title", row.label || row.email || row.key || ""));
  main.append(el("span", "resource-meta", [
    `${ta("usageRequests")} ${row.requests || 0}`,
    `${ta("usageTokens")} ${row.totalTokens || 0}`,
    `${ta("usageCost")} ${Number(row.costUsd || 0).toFixed(4)}`,
  ].join(" · ")));
  item.append(main);
  return item;
}

function renderUsageChart(series) {
  const target = $("usageChart");
  const points = Array.isArray(series?.points) ? series.points : [];
  const maximum = Math.max(1, ...points.map((point) => Number(point.totals?.requests || 0)));
  if (points.length === 0) {
    target.replaceChildren(el("p", "empty", ta("usageChartEmpty")));
    target.setAttribute("aria-label", ta("usageChartEmpty"));
    return;
  }
  const width = 640;
  const height = 120;
  const pad = 8;
  const slot = (width - pad * 2) / points.length;
  const barWidth = Math.max(1, slot - 2);
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", ta("usageChart", { bucket: series?.bucket || "day" }));
  points.forEach((point, index) => {
    const requests = Number(point.totals?.requests || 0);
    if (requests <= 0) return;
    const barHeight = Math.round(((height - pad * 2) * requests) / maximum);
    const bar = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    bar.setAttribute("class", "bar");
    bar.setAttribute("x", String(Math.round(pad + index * slot)));
    bar.setAttribute("y", String(height - pad - barHeight));
    bar.setAttribute("width", String(Math.round(barWidth)));
    bar.setAttribute("height", String(barHeight));
    bar.append(document.createElementNS("http://www.w3.org/2000/svg", "title"));
    bar.lastChild.textContent = `${point.start || ""}: ${requests}`;
    svg.append(bar);
  });
  target.replaceChildren(svg);
}

function renderUsage(data) {
  $("usageDetail").hidden = true;
  selectedRoute = null;
  renderRequests($("usageList"), $("usageEmpty"), $("usageCount"), data.rows || []);
}

async function loadRouteDetail(routeId) {
  const detail = $("usageDetail");
  detail.hidden = false;
  detail.replaceChildren(el("p", "detail-line", ta("routeLoading")));
  try {
    const data = await adminApi(`/routes/${routeId}`);
    selectedRoute = routeId;
    renderRouteDetail(data.route || {});
  } catch (error) {
    if (error instanceof AdminApiError && error.status === 404) {
      detail.replaceChildren(
        el("h3", "", ta("routeDetail")),
        el("p", "detail-line", ta("routeGone")),
      );
      return;
    }
    detail.replaceChildren(
      el("h3", "", ta("routeDetail")),
      el("p", "detail-line", error.message || ta("adminUnreachable")),
    );
  }
}

function renderRouteDetail(route) {
  const detail = $("usageDetail");
  // The management service answers the attempts as `attempts`, whichever
  // side they came from: a live trace or, after a restart, the usage
  // ledger. `tries` is their count.
  const tries = Array.isArray(route.attempts)
    ? route.attempts
    : Array.isArray(route.tries) ? route.tries : [];
  const lines = [
    [ta("detailRoute"), String(route.id || "")],
    [ta("detailTime"), route.time ? formatTime(route.time) : ""],
    [ta("detailAgent"), String(route.agent || "")],
    [ta("detailModel"), String(route.model || "")],
    [ta("detailProvider"), String(route.provider || "")],
    [ta("detailStatus"), String(route.status || "")],
    [ta("detailMillis"), `${route.ms || 0} ms`],
    [ta("detailTTFT"), route.ttft ? `${route.ttft} ms` : ""],
    [ta("detailTokens"), formatNumber(route.out || 0)],
    [ta("detailGroup"), route.group?.id || ""],
    [ta("detailError"), String(route.error || "")],
  ];
  const nodes = [el("h3", "", ta("routeDetail"))];
  if (route.source === "live") nodes.push(el("p", "detail-line", ta("detailSourceLive")));
  if (route.source === "usage") nodes.push(el("p", "detail-line", ta("detailSourceUsage")));
  for (const [label, value] of lines) {
    if (!value) continue;
    const line = el("p", "detail-line");
    line.append(el("b", "", label), document.createTextNode(value));
    nodes.push(line);
  }
  if (tries.length > 0) {
    nodes.push(el("p", "detail-line", ta("detailTries", { count: tries.length })));
    const list = el("ul", "tries");
    for (const item of tries) {
      list.append(el("li", "", [
        item.model || "",
        item.status ? `status ${item.status}` : "",
        item.millis ? `${item.millis} ms` : "",
        item.served || item.upstream || "",
        item.error || "",
      ].filter(Boolean).join(" · ")));
    }
    nodes.push(list);
  }
  detail.replaceChildren(...nodes);
}

function parseLimit(form) {
  const period = String(form.elements.period.value || "").trim();
  if (!period) return { limit: null, limitSet: true };
  const tokens = Number(String(form.elements.tokens.value || "").trim() || 0);
  const cost = Number(String(form.elements.cost.value || "").trim() || 0);
  if (!Number.isFinite(tokens) || tokens < 0 || !Number.isFinite(cost) || cost < 0) {
    throw new AdminApiError("invalid_key", ta("invalidLimit"));
  }
  if (tokens === 0 && cost === 0) return { limit: null, limitSet: true };
  return {
    limit: {
      period,
      ...(period === "days" ? { days: 1 } : {}),
      ...(period === "hours" ? { hours: 1 } : {}),
      ...(tokens > 0 ? { tokens } : {}),
      ...(cost > 0 ? { cost } : {}),
    },
    limitSet: true,
  };
}

function openKeyForm(key) {
  editingKey = key;
  const form = $("keyEditForm");
  form.hidden = false;
  $("keyEditTitle").textContent = ta("keyEdit");
  form.elements.name.value = key.name || "";
  form.elements.models.value = (key.models || []).join(", ");
  form.elements.period.value = key.limit?.period || "";
  form.elements.tokens.value = key.limit?.tokens ? String(key.limit.tokens) : "";
  form.elements.cost.value = key.limit?.cost ? String(key.limit.cost) : "";
  form.elements.off.checked = key.state === "disabled";
  $("keyEditNote").textContent = ta("keyPolicyNote");
  form.elements.name.focus();
}

async function saveKey(event) {
  event.preventDefault();
  if (!editingKey || adminBusy) return;
  const form = event.currentTarget;
  let limit;
  try {
    limit = parseLimit(form);
  } catch (error) {
    adminNotice(error.message, "error");
    return;
  }
  const body = {
    name: form.elements.name.value.trim(),
    models: form.elements.models.value
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
    off: form.elements.off.checked,
    reason: form.elements.reason.value.trim(),
    ...limit,
    expectedRevision: editingKey.revision,
  };
  try {
    adminBusy = true;
    await withApproval((extra) => adminApi(`/gateway/keys/${encodeURIComponent(editingKey.id)}`, {
      method: "PATCH",
      body: { ...body, ...extra },
    }));
    form.hidden = true;
    editingKey = null;
    await loadAdminTab();
  } catch (error) {
    adminNotice(highRiskHint(error), "error");
  } finally {
    adminBusy = false;
  }
}

function highRiskHint(error) {
  if (error instanceof AdminApiError && error.code === "approval_required") {
    return ta("approvalNeeded");
  }
  return error.message || ta("adminUnreachable");
}

// withApproval runs a high-risk write, and when the management service
// answers approval_required, asks for the approval's id once and retries.
// The approval is started and decided in the web console, where the
// approvers are; this page only cites it.
async function withApproval(run) {
  try {
    return await run({});
  } catch (error) {
    if (!(error instanceof AdminApiError) || error.code !== "approval_required") throw error;
    const approvalId = window.prompt(ta("approvalPrompt"), "");
    if (!approvalId) throw error;
    return run({ approvalId });
  }
}

async function rotateKey(key) {
  if (!window.confirm(ta("confirmRotateKey", { name: key.name || key.id }))) return;
  const reason = window.prompt(ta("changeReasonPrompt"), "");
  if (!reason) return;
  try {
    const result = await withApproval((extra) => adminApi(
      `/gateway/keys/${encodeURIComponent(key.id)}`,
      {
        method: "PATCH",
        body: { rotate: true, expectedRevision: key.revision, reason, ...extra },
      },
    ));
    window.prompt(ta("keySaveNow"), result.secret || "");
    await loadAdminTab();
  } catch (error) {
    adminNotice(highRiskHint(error), "error");
  }
}

async function removeKey(key) {
  if (!window.confirm(ta("confirmRemoveKey", { name: key.name || key.id }))) return;
  const reason = window.prompt(ta("changeReasonPrompt"), "");
  if (!reason) return;
  try {
    await withApproval((extra) => adminApi(
      `/gateway/keys/${encodeURIComponent(key.id)}`,
      {
        method: "PATCH",
        body: { remove: true, expectedRevision: key.revision, reason, ...extra },
      },
    ));
    await loadAdminTab();
  } catch (error) {
    adminNotice(highRiskHint(error), "error");
  }
}

async function startAdminLogin() {
  if (adminBusy) return;
  adminBusy = true;
  $("adminSignIn").disabled = true;
  $("adminSignIn").textContent = ta("adminSigningIn");
  try {
    await adminApi("/login", { method: "POST" });
    adminNotice(ta("adminLoginOpened"), "info");
    // The callback lands on this service; poll until the token is in.
    for (let attempt = 0; attempt < 150; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      const state = await adminApi("/status").catch(() => null);
      if (state?.signedIn) {
        adminState = state;
        adminBusy = false;
        $("adminSignIn").textContent = ta("adminSignIn");
        noticeEl.hidden = true;
        renderAdmin();
        return;
      }
      if (state && !state.loginPending && attempt > 2) break;
    }
    adminNotice(ta("adminExpired"), "warn");
  } catch (error) {
    adminNotice(error.message || ta("adminUnreachable"), "error");
  } finally {
    adminBusy = false;
    $("adminSignIn").disabled = false;
    $("adminSignIn").textContent = ta("adminSignIn");
  }
}

async function signOutAdmin() {
  try {
    await adminApi("/logout", { method: "POST" });
  } catch {
    // the token is dropped locally either way
  }
  adminState = { ...(adminState || {}), signedIn: false, user: null };
  renderAdmin();
}

function translateAdmin() {
  $("viewEmployee").textContent = ta("employee");
  $("viewAdmin").textContent = ta("administrator");
  $("adminSignIn").textContent = ta("adminSignIn");
  $("adminSignOut").textContent = ta("adminSignOut");
  $("adminRefresh").textContent = ta("adminRefresh");
  $("openConsole").textContent = ta("webConsole");
  $("consoleForm").elements.adminUrl.closest("label").querySelector("span").textContent =
    ta("consoleAddress");
  $("consoleForm").querySelector("button[type=submit]").textContent = ta("consoleSave");
  $("openConsoleSignedIn").textContent = ta("webConsole");
  $("providerAdd").textContent = ta("providerAdd");
  $("keyAdd").textContent = ta("keyAdd");
  const tabNames = {
    overview: "tabOverview",
    providers: "tabProviders",
    routing: "tabRouting",
    gateway: "tabGateway",
    resources: "tabResources",
    usage: "tabUsage",
    audit: "tabAudit",
  };
  $("resTitle").textContent = ta("resTitle");
  $("syncTitle").textContent = ta("syncTitle");
  $("auditTitle").textContent = ta("auditTitle");
  $("auditReadNote").textContent = ta("auditNote");
  for (const button of document.querySelectorAll("#adminTabs .tab")) {
    button.textContent = ta(tabNames[button.dataset.tab] || button.dataset.tab);
  }
  $("ovGatewayTitle").textContent = ta("ovGateway");
  $("ovCallsTitle").textContent = ta("ovCalls");
  $("ovRecentTitle").textContent = ta("ovRecent");
  $("providersTitle").textContent = ta("providers");
  $("routingTitle").textContent = ta("routing");
  $("gwTitle").textContent = ta("gateway");
  $("gwModelsTitle").textContent = ta("gatewayModels");
  $("gwKeysTitle").textContent = ta("gatewayKeys");
  $("gwDevicesTitle").textContent = ta("gatewayDevices");
  $("usageTitle").textContent = ta("usage");
  $("providerFormTitle").textContent = editingProvider ? ta("providerEdit") : ta("providerAdd");
  $("groupAdd").textContent = ta("groupAdd");
  $("groupFormTitle").textContent = editingGroup ? ta("groupEdit") : ta("groupAdd");
  $("keyEditTitle").textContent = ta("keyEdit");
  $("keyFormTitle").textContent = ta("keyAdd");
  const labels = {
    name: ta("providerName"),
    preset: ta("providerPresetField"),
    baseAPI: ta("providerBase"),
    key: ta("providerKey"),
    addKeys: ta("providerAddKeys"),
    models: ta("providerModels"),
    reason: ta("changeReason"),
  };
  for (const [name, label] of Object.entries(labels)) {
    const field = $("providerForm").elements[name]?.closest("label")?.querySelector("span");
    if (field) field.textContent = label;
  }
  const groupLabels = {
    id: ta("groupId"),
    name: ta("groupName"),
    members: ta("groupMembers"),
    match: ta("groupMatch"),
    routing: ta("groupRouting"),
    affinity: ta("groupAffinity"),
    off: ta("groupOff"),
    rules: ta("groupRules"),
    weights: ta("groupWeights"),
    reason: ta("changeReason"),
  };
  for (const [name, label] of Object.entries(groupLabels)) {
    const field = $("groupForm").elements[name]?.closest("label")?.querySelector("span");
    if (field) field.textContent = label;
  }
  const groupDisabled = $("groupForm").elements.disabled.closest("label");
  if (groupDisabled) {
    groupDisabled.lastChild.textContent = ` ${ta("groupDisabled")}`;
  }
  const offLabel = $("providerForm").elements.off.closest("label");
  if (offLabel) {
    offLabel.lastChild.textContent = ` ${ta("providerOff")}`;
  }
  for (const id of ["providerForm", "groupForm", "keyEditForm"]) {
    const save = $(id).querySelector("button[type=submit]");
    if (save) save.textContent = ta("save");
    const cancel = $(id).querySelector(`[data-close=${id}]`);
    if (cancel) cancel.textContent = ta("cancel");
  }
  const keyCreate = $("keyForm").querySelector("button[type=submit]");
  for (const formId of ["keyForm", "keyEditForm"]) {
    const label = $(formId).elements.reason?.closest("label")?.querySelector("span");
    if (label) label.textContent = ta("changeReason");
  }
  if (keyCreate) keyCreate.textContent = ta("keyCreate");
  const keyCancel = $("keyForm").querySelector("[data-close=keyForm]");
  if (keyCancel) keyCancel.textContent = ta("cancel");
}

$("viewEmployee").addEventListener("click", () => setView("employee"));
$("viewAdmin").addEventListener("click", () => setView("admin"));
$("adminSignIn").addEventListener("click", startAdminLogin);
$("adminSignOut").addEventListener("click", signOutAdmin);
$("adminRefresh").addEventListener("click", () => loadAdmin());
$("resDetailClose").addEventListener("click", () => { $("resDetail").hidden = true; });
$("auditFilter").addEventListener("submit", (event) => {
  event.preventDefault();
  loadAudit().catch((error) => adminNotice(error.message || ta("adminUnreachable"), "error"));
});
$("auditDetailClose").addEventListener("click", () => { $("auditDetail").hidden = true; });
$("consoleForm").addEventListener("submit", saveConsole);
$("providerAdd").addEventListener("click", () => openProviderForm(null));
$("providerForm").addEventListener("submit", saveProvider);
$("providerForm").querySelector("[data-close=providerForm]")
  .addEventListener("click", () => {
    $("providerForm").hidden = true;
    editingProvider = null;
  });
$("groupAdd").addEventListener("click", () => openGroupForm(null));
$("groupForm").addEventListener("submit", saveGroup);
$("groupForm").querySelector("[data-close=groupForm]")
  .addEventListener("click", () => {
    $("groupForm").hidden = true;
    editingGroup = null;
  });
$("keyAdd").addEventListener("click", () => {
  $("keyForm").hidden = false;
  $("keySecret").hidden = true;
  const form = $("keyForm");
  form.reset();
  form.elements.name.focus();
});
$("keyForm").addEventListener("submit", createKey);
$("keyForm").querySelector("[data-close=keyForm]")
  .addEventListener("click", () => {
    $("keyForm").hidden = true;
  });
$("keyEditForm").addEventListener("submit", saveKey);
$("keyEditForm").querySelector("[data-close=keyEditForm]")
  .addEventListener("click", () => {
    $("keyEditForm").hidden = true;
    editingKey = null;
  });

async function createKey(event) {
  event.preventDefault();
  if (adminBusy) return;
  const form = event.currentTarget;
  const body = {
    name: form.elements.name.value.trim(),
    models: form.elements.models.value
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
    readOnly: form.elements.readOnly.checked,
    reason: form.elements.reason.value.trim(),
  };
  try {
    adminBusy = true;
    const created = await adminApi("/gateway/keys", { method: "POST", body });
    const secret = $("keySecret");
    secret.hidden = false;
    secret.textContent = ta("keyShownOnce", { secret: created.secret || "" });
    form.elements.name.value = "";
    await loadAdminTab();
  } catch (error) {
    adminNotice(highRiskHint(error), "error");
  } finally {
    adminBusy = false;
  }
}
for (const button of document.querySelectorAll("#adminTabs .tab")) {
  button.addEventListener("click", () => selectTab(button.dataset.tab));
}
translateAdmin();
