// MTProto VPN Client для Windows
// Реализован на Go с использованием библиотеки Fyne для графического интерфейса.
// Работает в режиме purego (без CGO), поэтому не требует GCC.
// Весь код содержится в одном файле.
//
// Сборка для Windows:
//   go mod init mtproto-vpn-client
//   go get fyne.io/fyne/v2@latest
//   go build -tags purego -ldflags="-H windowsgui" -o mtproto_vpn_client.exe main.go
//
// Запуск:
//   Просто запустите mtproto_vpn_client.exe

package main

import (
	"encoding/hex"
	"fmt"
	"image/color"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// ============================================================================
// КОНСТАНТЫ И ПАРАМЕТРЫ
// ============================================================================

const (
	AppName    = "MTProto VPN"
	AppVersion = "1.0.0"
	DefaultPort = 443
)

// Фиолетовая цветовая палитра
var (
	PurplePrimary   = color.RGBA{R: 147, G: 51, B: 234, A: 255}  // #9333EA
	PurpleDark      = color.RGBA{R: 124, G: 58, B: 237, A: 255}  // #7C3AED
	PurpleLight     = color.RGBA{R: 167, G: 139, B: 250, A: 255} // #A78BFA
	PurpleBg        = color.RGBA{R: 26, G: 16, B: 37, A: 255}    // #1A1025
	PurpleSurface   = color.RGBA{R: 38, G: 24, B: 56, A: 255}    // #261838
	PurpleOnPrimary = color.RGBA{R: 255, G: 255, B: 255, A: 255}
	StatusConnected = color.RGBA{R: 34, G: 197, B: 94, A: 255}   // Зеленый
	StatusError     = color.RGBA{R: 239, G: 68, B: 68, A: 255}   // Красный
	StatusWarning   = color.RGBA{R: 234, G: 179, B: 8, A: 255}   // Желтый
)

// ============================================================================
// СТРУКТУРЫ ДАННЫХ
// ============================================================================

// AppConfig - конфигурация приложения
type AppConfig struct {
	Server       string `json:"server"`
	Port         int    `json:"port"`
	Secret       string `json:"secret"`
	DC           int    `json:"dc_id"`
	AutoConnect  bool   `json:"auto_connect"`
	Theme        string `json:"theme"`
}

// ConnectionState - состояние соединения
type ConnectionState int

const (
	StateDisconnected ConnectionState = iota
	StateConnecting
	StateConnected
	StateError
)

func (s ConnectionState) String() string {
	switch s {
	case StateDisconnected:
		return "Отключено"
	case StateConnecting:
		return "Подключение..."
	case StateConnected:
		return "Подключено"
	case StateError:
		return "Ошибка"
	default:
		return "Неизвестно"
	}
}

// TrafficStats - статистика трафика
type TrafficStats struct {
	BytesSent     uint64
	BytesReceived uint64
	StartTime     time.Time
	mu            sync.Mutex
}

func (ts *TrafficStats) AddSent(bytes uint64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.BytesSent += bytes
}

func (ts *TrafficStats) AddReceived(bytes uint64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.BytesReceived += bytes
}

func (ts *TrafficStats) GetSpeed() (sendSpeed, recvSpeed float64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	elapsed := time.Since(ts.StartTime).Seconds()
	if elapsed < 1 {
		return 0, 0
	}
	return float64(ts.BytesSent) / elapsed, float64(ts.BytesReceived) / elapsed
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d Б", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cБ", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// MTProtoClient - основной клиент
type MTProtoClient struct {
	config     *AppConfig
	conn       net.Conn
	state      ConnectionState
	stateMu    sync.RWMutex
	stats      *TrafficStats
	authKey    []byte
	serverAddr string
	ctxCancel  context.CancelFunc
	logs       []string
	logMu      sync.Mutex
}

// GlobalState - глобальное состояние приложения
type GlobalState struct {
	client  *MTProtoClient
	config  *AppConfig
	app     fyne.App
	window  fyne.Window
	status  *widget.Label
	logView *widget.Label
	statsLabel *widget.Label
	connectBtn *widget.Button
	serverEntry *widget.Entry
	portEntry *widget.Entry
	secretEntry *widget.Entry
	dcEntry *widget.Entry
}

var globalState = &GlobalState{}

// ============================================================================
// ФУНКЦИИ УПРАВЛЕНИЯ КОНФИГУРАЦИЕЙ
// ============================================================================

func getConfigPath() (string, error) {
	var configDir string
	
	if os.Getenv("APPDATA") != "" {
		configDir = filepath.Join(os.Getenv("APPDATA"), "MTProtoVPN")
	} else if os.Getenv("HOME") != "" {
		configDir = filepath.Join(os.Getenv("HOME"), ".mtproto_vpn")
	} else {
		configDir = "."
	}
	
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", err
	}
	
	return filepath.Join(configDir, "config.json"), nil
}

func LoadConfig() (*AppConfig, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return getDefaultConfig(), nil
	}
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		return getDefaultConfig(), nil
	}
	
	var config AppConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return getDefaultConfig(), nil
	}
	
	if config.Port == 0 {
		config.Port = DefaultPort
	}
	if config.DC == 0 {
		config.DC = 2
	}
	
	return &config, nil
}

func SaveConfig(config *AppConfig) error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(configPath, data, 0644)
}

func getDefaultConfig() *AppConfig {
	return &AppConfig{
		Server:      "",
		Port:        DefaultPort,
		Secret:      "",
		DC:          2,
		AutoConnect: false,
		Theme:       "purple",
	}
}

// ParseProxyURL парсит ссылки вида tg://proxy или mtproto://
func ParseProxyURL(rawURL string) (*AppConfig, error) {
	rawURL = strings.TrimSpace(rawURL)
	
	// Обработка tg://proxy ссылок
	if strings.HasPrefix(rawURL, "tg://proxy") || strings.HasPrefix(rawURL, "https://t.me/proxy") {
		var u *url.URL
		var err error
		
		if strings.HasPrefix(rawURL, "https://") {
			// Конвертируем https://t.me/proxy?... в url
			u, err = url.Parse(rawURL)
		} else {
			u, err = url.Parse(strings.Replace(rawURL, "tg://proxy", "mtproto://proxy", 1))
		}
		
		if err != nil {
			return nil, err
		}
		
		query := u.Query()
		
		server := query.Get("server")
		if server == "" {
			// Пробуем извлечь из host для tg://
			server = u.Hostname()
		}
		
		portStr := query.Get("port")
		if portStr == "" {
			portStr = u.Port()
		}
		port, _ := strconv.Atoi(portStr)
		if port == 0 {
			port = DefaultPort
		}
		
		secret := query.Get("secret")
		dcStr := query.Get("dc")
		dc, _ := strconv.Atoi(dcStr)
		if dc == 0 {
			dc = 2
		}
		
		return &AppConfig{
			Server: server,
			Port:   port,
			Secret: secret,
			DC:     dc,
		}, nil
	}
	
	// Обработка mtproto:// ссылок
	if strings.HasPrefix(rawURL, "mtproto://") {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}
		
		server := u.Hostname()
		portStr := u.Port()
		port, _ := strconv.Atoi(portStr)
		if port == 0 {
			port = DefaultPort
		}
		
		query := u.Query()
		secret := query.Get("secret")
		if secret == "" && u.Path != "" {
			secret = strings.TrimPrefix(u.Path, "/")
		}
		
		dcStr := query.Get("dc")
		dc, _ := strconv.Atoi(dcStr)
		
		return &AppConfig{
			Server: server,
			Port:   port,
			Secret: secret,
			DC:     dc,
		}, nil
	}
	
	return nil, fmt.Errorf("неподдерживаемый формат URL")
}

// DecodeSecret декодирует секрет MTProto
func DecodeSecret(secret string) ([]byte, error) {
	// Удаляем возможные префиксы
	secret = strings.TrimSpace(secret)
	
	// Если начинается с ee, это HTTP CONNECT прокси
	if strings.HasPrefix(secret, "ee") {
		// Формат: ee + hex(домен:порт) + остальное
		hexPart := secret[2:]
		if len(hexPart) < 4 {
			return nil, fmt.Errorf("неверный формат секрета")
		}
		
		// Декодируем домен и порт
		domainLen, err := strconv.ParseInt(hexPart[:2], 16, 32)
		if err != nil {
			return nil, err
		}
		
		hexDomain := hexPart[2 : 2+domainLen*2]
		domain, err := hex.DecodeString(hexDomain)
		if err != nil {
			return nil, err
		}
		
		// Оставшаяся часть - это ключ
		keyHex := hexPart[2+domainLen*2:]
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, err
		}
		
		return key, nil
	}
	
	// Обычный hex секрет
	if len(secret)%2 == 0 {
		return hex.DecodeString(secret)
	}
	
	// Base64 секрет
	return base64Decode(secret)
}

func base64Decode(s string) ([]byte, error) {
	// Стандартный base64
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	
	// URL-safe base64
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	
	return nil, fmt.Errorf("не удалось декодировать secret")
}

// ============================================================================
// КРИПТОГРАФИЯ MTProto (упрощенная)
// ============================================================================

// В реальной реализации здесь была бы полная криптография MTProto 2.0
// Для демонстрации используем заглушки

func createAuthKey(secret []byte) []byte {
	// В реальности здесь генерируется DH обмен
	// Для демо просто используем secret как часть ключа
	key := make([]byte, 256)
	copy(key, secret)
	
	// Заполняем остальное случайными данными
	rand.Seed(time.Now().UnixNano())
	for i := len(secret); i < 256; i++ {
		key[i] = byte(rand.Intn(256))
	}
	
	return key
}

// ============================================================================
// СЕТЕВЫЕ ФУНКЦИИ
// ============================================================================

func NewMTProtoClient(config *AppConfig) *MTProtoClient {
	authKey := createAuthKey([]byte(config.Secret))
	
	return &MTProtoClient{
		config:     config,
		state:      StateDisconnected,
		stats:      &TrafficStats{StartTime: time.Now()},
		authKey:    authKey,
		serverAddr: fmt.Sprintf("%s:%d", config.Server, config.Port),
		logs:       make([]string, 0),
	}
}

func (c *MTProtoClient) Connect() error {
	c.stateMu.Lock()
	if c.state == StateConnecting || c.state == StateConnected {
		c.stateMu.Unlock()
		return fmt.Errorf("уже подключено")
	}
	c.state = StateConnecting
	c.stateMu.Unlock()
	
	c.addLog("Подключение к " + c.serverAddr)
	
	// TCP соединение
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	
	conn, err := dialer.Dial("tcp", c.serverAddr)
	if err != nil {
		c.setState(StateError)
		c.addLog("Ошибка подключения: " + err.Error())
		return err
	}
	
	c.conn = conn
	c.setState(StateConnected)
	c.stats.StartTime = time.Now()
	c.addLog("Успешное подключение!")
	
	// Запускаем чтение в фоне
	go c.readLoop()
	
	return nil
}

func (c *MTProtoClient) Disconnect() error {
	c.stateMu.Lock()
	if c.state != StateConnected {
		c.stateMu.Unlock()
		return nil
	}
	c.stateMu.Unlock()
	
	c.addLog("Отключение...")
	
	if c.conn != nil {
		c.conn.Close()
	}
	
	c.setState(StateDisconnected)
	c.addLog("Отключено")
	
	return nil
}

func (c *MTProtoClient) setState(state ConnectionState) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.state = state
}

func (c *MTProtoClient) getState() ConnectionState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

func (c *MTProtoClient) readLoop() {
	buffer := make([]byte, 4096)
	
	for {
		if c.conn == nil {
			return
		}
		
		n, err := c.conn.Read(buffer)
		if err != nil {
			return
		}
		
		c.stats.AddReceived(uint64(n))
	}
}

func (c *MTProtoClient) addLog(message string) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	
	timestamp := time.Now().Format("15:04:05")
	logEntry := fmt.Sprintf("[%s] %s", timestamp, message)
	
	c.logs = append(c.logs, logEntry)
	
	if len(c.logs) > 50 {
		c.logs = c.logs[1:]
	}
	
	log.Println(logEntry)
}

func (c *MTProtoClient) getLogs() string {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	
	if len(c.logs) == 0 {
		return "Нет записей лога"
	}
	
	return strings.Join(c.logs, "\n")
}

func (c *MTProtoClient) GetStats() (uint64, uint64, float64, float64) {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()
	
	sendSpeed, recvSpeed := 0.0, 0.0
	elapsed := time.Since(c.stats.StartTime).Seconds()
	if elapsed > 0 {
		sendSpeed = float64(c.stats.BytesSent) / elapsed
		recvSpeed = float64(c.stats.BytesReceived) / elapsed
	}
	
	return c.stats.BytesSent, c.stats.BytesReceived, sendSpeed, recvSpeed
}

// ============================================================================
// GUI ФИОЛЕТОВАЯ ТЕМА
// ============================================================================

type PurpleTheme struct {
	fyne.Theme
}

func NewPurpleTheme() *PurpleTheme {
	return &PurpleTheme{}
}

func (p *PurpleTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return PurplePrimary
	case theme.ColorNameBackground:
		return PurpleBg
	case theme.ColorNameButton:
		return PurpleDark
	case theme.ColorNameDisabled:
		return color.Gray{Y: 80}
	case theme.ColorNamePlaceHolder:
		return color.Gray{Y: 100}
	case theme.ColorNameShadow:
		return color.RGBA{R: 0, G: 0, B: 0, A: 180}
	default:
		return p.Theme.Color(name, variant)
	}
}

func (p *PurpleTheme) Font(style fyne.TextStyle) fyne.Resource {
	return p.Theme.Font(style)
}

func (p *PurpleTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return p.Theme.Icon(name)
}

func (p *PurpleTheme) Size(name fyne.ThemeSizeName) float32 {
	return p.Theme.Size(name)
}

// ============================================================================
// ОСНОВНОЙ ИНТЕРФЕЙС
// ============================================================================

func createUI() fyne.CanvasObject {
	// Заголовок
	title := widget.NewLabelWithStyle("MTProto VPN Client", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	title.TextSize = 24
	title.Color = PurpleLight
	
	// Поля ввода
	globalState.serverEntry = widget.NewEntry()
	globalState.serverEntry.SetPlaceHolder("Сервер (например: peyk.acharbashi.info)")
	
	globalState.portEntry = widget.NewEntry()
	globalState.portEntry.SetPlaceHolder("Порт (443)")
	globalState.portEntry.SetText(strconv.Itoa(DefaultPort))
	
	globalState.secretEntry = widget.NewEntry()
	globalState.secretEntry.SetPlaceHolder("Secret ключ")
	globalState.secretEntry.MultiLine = true
	globalState.secretEntry.Wrapping = fyne.TextWrapBreak
	
	globalState.dcEntry = widget.NewEntry()
	globalState.dcEntry.SetPlaceHolder("DC ID")
	globalState.dcEntry.SetText("2")
	
	// Форма настроек
	form := container.NewVBox(
		widget.NewLabelWithStyle("Настройки подключения", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewGridWithColumns(2,
			widget.NewLabel("Сервер:"),
			globalState.serverEntry,
		),
		container.NewGridWithColumns(2,
			widget.NewLabel("Порт:"),
			globalState.portEntry,
		),
		container.NewGridWithColumns(2,
			widget.NewLabel("Secret:"),
			globalState.secretEntry,
		),
		container.NewGridWithColumns(2,
			widget.NewLabel("DC ID:"),
			globalState.dcEntry,
		),
	)
	
	// Статус подключения
	globalState.status = widget.NewLabel("Статус: Отключено")
	globalState.status.Alignment = fyne.TextAlignCenter
	
	// Кнопка подключения
	globalState.connectBtn = widget.NewButton("Подключиться", onConnectToggle)
	globalState.connectBtn.Importance = widget.HighImportance
	
	// Статистика
	globalState.statsLabel = widget.NewLabel("📊 Трафик: 0 Б отправлено | 0 Б получено")
	globalState.statsLabel.Alignment = fyne.TextAlignCenter
	
	// Лог
	globalState.logView = widget.NewLabel("Нет записей лога")
	globalState.logView.Wrapping = fyne.TextWrapBreak
	globalState.logView.TextSize = 10
	
	logScroll := container.NewScroll(globalState.logView)
	logScroll.SetMinSize(fyne.NewSize(400, 150))
	
	// Кнопки импорта/экспорта
	importBtn := widget.NewButton("📥 Импорт из буфера", onImport)
	exportBtn := widget.NewButton("📤 Экспорт конфига", onExport)
	clearBtn := widget.NewButton("🗑 Очистить лог", onClearLog)
	
	buttonsBox := container.NewHBox(importBtn, exportBtn, clearBtn)
	
	// Основная компоновка
	content := container.NewVBox(
		title,
		widget.NewSeparator(),
		form,
		widget.NewSeparator(),
		globalState.status,
		globalState.connectBtn,
		globalState.statsLabel,
		widget.NewLabelWithStyle("Лог событий:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		logScroll,
		widget.NewSeparator(),
		buttonsBox,
	)
	
	return content
}

func onConnectToggle() {
	if globalState.client != nil && globalState.client.getState() == StateConnected {
		// Отключение
		go func() {
			globalState.client.Disconnect()
			updateUI()
		}()
		return
	}
	
	// Подключение
	server := globalState.serverEntry.Text
	portStr := globalState.portEntry.Text
	secret := globalState.secretEntry.Text
	dcStr := globalState.dcEntry.Text
	
	if server == "" || secret == "" {
		dialog.ShowError(fmt.Errorf("Заполните поля Сервер и Secret"), globalState.window)
		return
	}
	
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		dialog.ShowError(fmt.Errorf("Неверный номер порта"), globalState.window)
		return
	}
	
	dc, _ := strconv.Atoi(dcStr)
	if dc == 0 {
		dc = 2
	}
	
	config := &AppConfig{
		Server: server,
		Port:   port,
		Secret: secret,
		DC:     dc,
	}
	
	// Сохраняем конфиг
	SaveConfig(config)
	
	// Создаем и подключаем клиент
	globalState.client = NewMTProtoClient(config)
	
	go func() {
		err := globalState.client.Connect()
		updateUI()
		if err != nil {
			dialog.ShowError(err, globalState.window)
		}
	}()
	
	updateUI()
}

func updateUI() {
	if globalState.client == nil {
		globalState.status.SetText("Статус: Отключено")
		globalState.status.Color = theme.Color(theme.ColorNameForeground)
		globalState.connectBtn.SetText("Подключиться")
		return
	}
	
	state := globalState.client.getState()
	globalState.status.SetText("Статус: " + state.String())
	
	switch state {
	case StateConnected:
		globalState.status.Color = StatusConnected
		globalState.connectBtn.SetText("Отключиться")
	case StateConnecting:
		globalState.status.Color = StatusWarning
		globalState.connectBtn.SetText("Подключение...")
		globalState.connectBtn.Disable()
		time.AfterFunc(2*time.Second, func() {
			globalState.connectBtn.Enable()
			updateUI()
		})
		return
	case StateError:
		globalState.status.Color = StatusError
		globalState.connectBtn.SetText("Подключиться")
	default:
		globalState.status.Color = theme.Color(theme.ColorNameForeground)
		globalState.connectBtn.SetText("Подключиться")
	}
	
	// Обновляем лог
	globalState.logView.SetText(globalState.client.getLogs())
	
	// Обновляем статистику
	sent, recv, sendSpd, recvSpd := globalState.client.GetStats()
	statsText := fmt.Sprintf("📊 Трафик: %s отправлено | %s получено\n⬆ %.2f КБ/с | ⬇ %.2f КБ/с",
		formatBytes(sent), formatBytes(recv), sendSpd/1024, recvSpd/1024)
	globalState.statsLabel.SetText(statsText)
	
	globalState.window.Canvas().Refresh(globalState.status)
	globalState.window.Canvas().Refresh(globalState.connectBtn)
	globalState.window.Canvas().Refresh(globalState.logView)
	globalState.window.Canvas().Refresh(globalState.statsLabel)
}

func onImport() {
	// Простая вставка из буфера через диалог
	input := widget.NewEntry()
	input.MultiLine = true
	input.Wrapping = fyne.TextWrapBreak
	input.SetPlaceHolder("Вставьте ссылку tg://proxy или mtproto://...")
	
	win := fyne.CurrentApp().NewWindow("Импорт конфигурации")
	win.SetContent(container.NewVBox(
		widget.NewLabel("Вставьте ссылку на прокси:"),
		input,
		widget.NewButton("Импортировать", func() {
			config, err := ParseProxyURL(input.Text)
			if err != nil {
				dialog.ShowError(err, win)
				return
			}
			
			globalState.serverEntry.SetText(config.Server)
			globalState.portEntry.SetText(strconv.Itoa(config.Port))
			globalState.secretEntry.SetText(config.Secret)
			globalState.dcEntry.SetText(strconv.Itoa(config.DC))
			
			win.Close()
			dialog.ShowInformation("Успех", "Конфигурация импортирована!", globalState.window)
		}),
		widget.NewButton("Отмена", func() {
			win.Close()
		}),
	))
	win.Resize(fyne.NewSize(500, 300))
	win.Show()
}

func onExport() {
	if globalState.config == nil {
		dialog.ShowInformation("Информация", "Нет сохраненной конфигурации", globalState.window)
		return
	}
	
	configJSON, _ := json.MarshalIndent(globalState.config, "", "  ")
	
	// Показываем конфиг в диалоге
	output := widget.NewEntry()
	output.SetText(string(configJSON))
	output.MultiLine = true
	output.ReadOnly = true
	
	win := fyne.CurrentApp().NewWindow("Экспорт конфигурации")
	win.SetContent(container.NewVBox(
		widget.NewLabel("Конфигурация (JSON):"),
		output,
		widget.NewButton("Закрыть", func() {
			win.Close()
		}),
	))
	win.Resize(fyne.NewSize(500, 400))
	win.Show()
}

func onClearLog() {
	if globalState.client != nil {
		globalState.client.logMu.Lock()
		globalState.client.logs = make([]string, 0)
		globalState.client.logMu.Unlock()
		updateUI()
	}
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	// Инициализация приложения Fyne
	myApp := app.NewWithID("com.mtproto.vpn")
	globalState.app = myApp
	
	// Создаем главное окно
	globalState.window = myApp.NewWindow(AppName)
	globalState.window.Resize(fyne.NewSize(600, 700))
	
	// Загружаем конфиг
	config, err := LoadConfig()
	if err == nil {
		globalState.config = config
		globalState.serverEntry = widget.NewEntry()
		globalState.serverEntry.SetText(config.Server)
		globalState.portEntry = widget.NewEntry()
		globalState.portEntry.SetText(strconv.Itoa(config.Port))
		globalState.secretEntry = widget.NewEntry()
		globalState.secretEntry.SetText(config.Secret)
		globalState.dcEntry = widget.NewEntry()
		globalState.dcEntry.SetText(strconv.Itoa(config.DC))
	}
	
	// Создаем UI
	content := createUI()
	globalState.window.SetContent(content)
	
	// Запускаем обновление статистики
	go func() {
		for {
			time.Sleep(1 * time.Second)
			if globalState.client != nil && globalState.client.getState() == StateConnected {
				updateUI()
			}
		}
	}()
	
	// Показываем окно
	globalState.window.ShowAndRun()
}
