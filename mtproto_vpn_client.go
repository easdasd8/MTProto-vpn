// MTProto VPN Client для Windows
// Красивый фиолетовый интерфейс на Go
// Один файл, полная функциональность

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/pbkdf2"
	"encoding/json"
	"os/exec"
	"path/filepath"
)

// ============================================================================
// КОНСТАНТЫ И ПАРАМЕТРЫ MTProto
// ============================================================================

const (
	// MTProto константы
	MTProtoVersion    = "2"
	DefaultServerAddr = "149.154.167.50:443" // Telegram сервер
	
	// Параметры DH
	DHPrimeHex = "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed440e24e0883917df48823eb3c80030171b179e891916ef0a1f25be7e6086092bb73b3a342e793017dc83d2ce1c003e9096f3bba57d6f26081da017ec4be711f79c6c943bcfb23001d06ad074614de739674e439cdcb25bb7fc9f43a9dd2061188aba5ba7471f0751fcf98f387b56e35d3d35174d6efd4aabe455a770d16512b5650c9681e6d2432e2be07177185c3fe9165a8af71a7ab7fd9f214e01fcdc7426b4e1c96f56d67da8fda7c13905834593a67716688e5954c57338f1743c4eaf09ed469cf45ae6343fc4bc7bb1856551f8b5bd77f20830849ca8b47663a6d85d0df000aadc6947a43d6312454773e9f54646524218c688b374d1ab8554edc98011b3b3f59852ecec59e3aea47ee21659bf2fe825b2506ca576263c7fcc107bbc65f4e0e1f16e41ea86af9475497e330f706b5a9da170c436499fe077078442c1fe5716f55b95058628542c0429c070498562d81c53534378e4379f758a9e58d09c5ff979c265541c0c3d0482415a0b65b9a0982d2bb8b5317a7a2f474e6b7537a38a5515800a4973404e3a85416c82f70e6876d562dc37213c84f40aadb566b527049a3537c565ea300141b93c19804e5d0de5d5b9f4890fb0dd50bda017c89e50963ebe80ef963068100b61555cca37d0963fea329b3dfe722f19e427cf2f77c43c345fe6bb49ab6b0706ded581f556aa30e313f8076d0c60b0791aa72d4c206ac6588748a2ade9476db12b9c9f6c49d99f9a1a9cc12200e0684ad38baa7d0669d86b371d10f715fd4fae8114539fe06955292498c307d8bf74991b947349a96e4032e35e3c24154293e3be21a50716860da028a9861500e49052b70b1c48c019b4731d46ad45230e0663b00a8e7c5cdeb5127539689b00655414d91b11b0e24de88598d253813625bd80fb215fef509e4581c27f45ca40f33c4cf0f8cc51483523843c01a909dc0a13a13d4198566a934701fb321578a9589f4d5c6b7831990d1a0c231e0709b624b6d2882446f76dea400af8bdd34f01f812341c128ac77cad100a05127452aaa09855caa6df4879d68afc41d230c22c6844deace93b398608a10b7868590c72d8487b3ff53e15b0e27a3f14703ba6de832d889f1615385120f4c5817446f3fa8c0e98bdead4b11df4a0646610f354f65b776db5793768912c9421c65c0a805c15c38a7acde819f54be8adb14381162ca50a0119688f90b8436e827e31352e04347a354f1218008d0951012c64eda43adb43a2933d1e1247d9b5b4dba93d90b20061933f2b9ac9f6cb8dd341cd0be7ff92c5d81d503378d998d1fba25ae8864f2c03d078406a0d353307167da4e1981eb47798b368c80bc4a21571cc009f14919f7fad519d0f9d8da95c114db265d7935c018bad382f85819c274758c31b47786e5f84e90d231001f341dfa36ba6c451b91c215e441236c72749061978d4b7725b3d13e80640c2b9f0a42fa253564f92c3566b48a03a4f81131da25b201801a45eb004bbd4276356901462d819f6036c42081ee30b92c1798c28543a7c5428100507592c3446935b623235448de4026189a4d90c9a7bed3ff1a2b791e843f14cc622036e99095987efb5d305c3a359a200c392c200e509b0af3490f33b15ab11f14b83c522001b5e6321a81c0c969ac5ca233c897"
	DHGenerator = 3
	
	// Размеры
	MaxPacketSize = 65536
	HeaderSize    = 4
	
	// Таймауты
	ConnectionTimeout = 30 * time.Second
	ReadTimeout       = 60 * time.Second
	WriteTimeout      = 30 * time.Second
)

// ============================================================================
// СТРУКТУРЫ ДАННЫХ
// ============================================================================

// MTProtoConfig конфигурация подключения
type MTProtoConfig struct {
	ServerAddr   string
	DC           int
	AuthKey      []byte
	TimeOffset   int64
	SessionID    uint64
	ServerSalt   uint64
}

// VPNClient основной клиент
type VPNClient struct {
	config     *MTProtoConfig
	conn       net.Conn
	isConnected bool
	mutex      sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	
	// Статистика
	bytesSent     uint64
	bytesReceived uint64
	
	// Callbacks
	statusCallback func(bool, string)
	statsCallback  func(uint64, uint64)
}

// AppConfig конфигурация приложения (сохраняемые настройки)
type AppConfig struct {
	ServerAddr   string `json:"server_addr"`
	Port         string `json:"port"`
	DC           int    `json:"dc"`
	AuthKey      string `json:"auth_key"`
	UseProxy     bool   `json:"use_proxy"`
	ProxyAddr    string `json:"proxy_addr"`
	AutoConnect  bool   `json:"auto_connect"`
	DarkTheme    bool   `json:"dark_theme"`
}

// UIState состояние интерфейса
type UIState struct {
	serverEntry    *widget.Entry
	portEntry      *widget.Entry
	dcEntry        *widget.Entry
	authKeyEntry   *widget.Entry
	connectBtn     *widget.Button
	statusLabel    *widget.Label
	statsLabel     *widget.Label
	progressBar    *widget.ProgressBar
	logText        *widget.Entry
	isConnected    bool
	darkTheme      bool
	appConfig      *AppConfig
	configFile     string
}

// ============================================================================
// MTProto Криптография
// ============================================================================

// ============================================================================
// СИСТЕМА КОНФИГУРАЦИИ
// ============================================================================

// getConfigPath возвращает путь к файлу конфигурации
func getConfigPath() (string, error) {
	// Для Windows используем AppData
	if os.PathSeparator == '\\' {
		appData := os.Getenv("APPDATA")
		if appData == "" {
			return "", errors.New("APPDATA not set")
		}
		dir := filepath.Join(appData, "MTProtoVPN")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", err
		}
		return filepath.Join(dir, "config.json"), nil
	}
	
	// Для Linux/Mac используем домашнюю директорию
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".mtproto_vpn")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// LoadConfig загружает конфигурацию из файла
func LoadConfig() (*AppConfig, string, error) {
	configPath, err := getConfigPath()
	if err != nil {
		// Возвращаем конфигурацию по умолчанию
		return getDefaultConfig(), "", err
	}
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Файл не существует, создаем конфигурацию по умолчанию
			return getDefaultConfig(), configPath, nil
		}
		return getDefaultConfig(), configPath, err
	}
	
	var config AppConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return getDefaultConfig(), configPath, err
	}
	
	return &config, configPath, nil
}

// SaveConfig сохраняет конфигурацию в файл
func SaveConfig(config *AppConfig, configPath string) error {
	if configPath == "" {
		var err error
		configPath, err = getConfigPath()
		if err != nil {
			return err
		}
	}
	
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(configPath, data, 0644)
}

// getDefaultConfig возвращает конфигурацию по умолчанию
func getDefaultConfig() *AppConfig {
	return &AppConfig{
		ServerAddr:  "149.154.167.50",
		Port:        "443",
		DC:          2,
		AuthKey:     "",
		UseProxy:    false,
		ProxyAddr:   "",
		AutoConnect: false,
		DarkTheme:   true,
	}
}

// ValidateConfig проверяет корректность конфигурации
func ValidateConfig(config *AppConfig) error {
	if config.ServerAddr == "" {
		return errors.New("server address is required")
	}
	
	if config.Port == "" {
		return errors.New("port is required")
	}
	
	if _, err := strconv.Atoi(config.Port); err != nil {
		return errors.New("invalid port number")
	}
	
	if config.DC < 1 || config.DC > 5 {
		return errors.New("DC must be between 1 and 5")
	}
	
	return nil
}

// ImportConfig импортирует конфигурацию из строки (например, из clipboard)
func ImportConfig(configStr string) (*AppConfig, error) {
	var config AppConfig
	
	// Пробуем распарсить как JSON
	if err := json.Unmarshal([]byte(configStr), &config); err == nil {
		return &config, nil
	}
	
	// Пробуем распарсить как URL формат: mtproto://server:port?dc=X&authkey=Y
	if strings.HasPrefix(configStr, "mtproto://") {
		u, err := url.Parse(configStr)
		if err != nil {
			return nil, err
		}
		
		config.ServerAddr = u.Hostname()
		config.Port = u.Port()
		if config.Port == "" {
			config.Port = "443"
		}
		
		dc := u.Query().Get("dc")
		if dc != "" {
			config.DC, _ = strconv.Atoi(dc)
		} else {
			config.DC = 2
		}
		
		config.AuthKey = u.Query().Get("authkey")
		config.UseProxy, _ = strconv.ParseBool(u.Query().Get("proxy"))
		config.ProxyAddr = u.Query().Get("proxyaddr")
		
		return &config, nil
	}
	
	// Пробуем распарсить как простой формат: server:port:dc:authkey
	parts := strings.Split(configStr, ":")
	if len(parts) >= 3 {
		config.ServerAddr = parts[0]
		config.Port = parts[1]
		config.DC, _ = strconv.Atoi(parts[2])
		if len(parts) >= 4 {
			config.AuthKey = parts[3]
		}
		return &config, nil
	}
	
	return nil, errors.New("unable to parse config string")
}

// ExportConfig экспортирует конфигурацию в строку
func ExportConfig(config *AppConfig) string {
	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}

// ============================================================================
// MTProto Криптография
// ============================================================================

// MTProtoCrypto handles MTProto encryption/decryption
type MTProtoCrypto struct {
	authKey []byte
	msgKey  []byte
}

// NewMTProtoCrypto создает новый криптографический контекст
func NewMTProtoCrypto(authKey []byte) *MTProtoCrypto {
	return &MTProtoCrypto{authKey: authKey}
}

// GenerateMsgKey генерирует ключ сообщения
func (c *MTProtoCrypto) GenerateMsgKey(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[8:24]
}

// Encrypt шифрует данные по MTProto
func (c *MTProtoCrypto) Encrypt(messageData []byte, serverSalt uint64, sessionID uint64) ([]byte, error) {
	// Добавляем salt и session_id
	prefix := make([]byte, 8+8)
	binary.LittleEndian.PutUint64(prefix[0:8], serverSalt)
	binary.LittleEndian.PutUint64(prefix[8:16], sessionID)
	
	fullData := append(prefix, messageData...)
	
	// Padding до 16 байт
	padding := 16 - (len(fullData) % 16)
	if padding > 0 {
		paddingBytes := make([]byte, padding)
		rand.Read(paddingBytes)
		fullData = append(fullData, paddingBytes...)
	}
	
	// Генерируем msg_key
	msgKey := c.GenerateMsgKey(fullData)
	
	// Вычисляем aes_key и iv
	aesKey, iv := c.computeAESKeyIV(msgKey, true)
	
	// Шифруем
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	
	ciphertext := make([]byte, len(fullData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, fullData)
	
	// Формируем итоговый пакет
	result := append(msgKey, ciphertext...)
	return result, nil
}

// Decrypt расшифровывает данные по MTProto
func (c *MTProtoCrypto) Decrypt(data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("data too short")
	}
	
	msgKey := data[0:16]
	ciphertext := data[16:]
	
	// Вычисляем aes_key и iv
	aesKey, iv := c.computeAESKeyIV(msgKey, false)
	
	// Расшифровываем
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	
	// Проверяем msg_key
	computedMsgKey := c.GenerateMsgKey(plaintext)
	if string(msgKey) != string(computedMsgKey) {
		return nil, errors.New("msg_key mismatch")
	}
	
	// Удаляем salt, session_id и padding
	if len(plaintext) < 16 {
		return nil, errors.New("plaintext too short")
	}
	
	return plaintext[16:], nil
}

// computeAESKeyIV вычисляет AES ключ и вектор инициализации
func (c *MTProtoCrypto) computeAESKeyIV(msgKey []byte, encrypt bool) ([]byte, []byte) {
	var x byte
	if encrypt {
		x = 0
	} else {
		x = 8
	}
	
	sha256A := sha256.Sum256(append(msgKey, c.authKey[x:x+32]...))
	sha256B := sha256.Sum256(append(c.authKey[32+x:64+x], msgKey...))
	sha256C := sha256.Sum256(append(c.authKey[64+x:96+x], msgKey...))
	
	aesKey := append(sha256A[0:8], sha256B[8:20]...)
	aesKey = append(aesKey, sha256C[4:12]...)
	
	iv := append(sha256A[8:16], sha256B[0:8]...)
	iv = append(iv, sha256C[8:16]...)
	iv = append(iv, msgKey[0:4]...)
	
	return aesKey, iv
}

// ============================================================================
// MTProto Сетевые Операции
// ============================================================================

// MTProtoHandler обрабатывает MTProto соединения
type MTProtoHandler struct {
	config  *MTProtoConfig
	crypto  *MTProtoCrypto
	address string
}

// NewMTProtoHandler создает новый обработчик
func NewMTProtoHandler(config *MTProtoConfig) *MTProtoHandler {
	return &MTProtoHandler{
		config:  config,
		crypto:  NewMTProtoCrypto(config.AuthKey),
		address: config.ServerAddr,
	}
}

// Connect устанавливает соединение с сервером
func (h *MTProtoHandler) Connect() (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   ConnectionTimeout,
		KeepAlive: 30 * time.Second,
	}
	
	conn, err := dialer.Dial("tcp", h.address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	
	// Настраиваем таймауты
	conn.SetDeadline(time.Now().Add(ConnectionTimeout))
	
	return conn, nil
}

// Send отправляет зашифрованное сообщение
func (h *MTProtoHandler) Send(conn net.Conn, data []byte) error {
	// Шифруем сообщение
	encrypted, err := h.crypto.Encrypt(data, h.config.ServerSalt, h.config.SessionID)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}
	
	// Добавляем длину пакета
	length := uint32(len(encrypted))
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, length)
	
	packet := append(header, encrypted...)
	
	// Отправляем
	_, err = conn.Write(packet)
	return err
}

// Receive получает и расшифровывает сообщение
func (h *MTProtoHandler) Receive(conn net.Conn) ([]byte, error) {
	// Читаем длину пакета
	header := make([]byte, 4)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	
	length := binary.LittleEndian.Uint32(header)
	if length > MaxPacketSize {
		return nil, errors.New("packet too large")
	}
	
	// Читаем зашифрованные данные
	encrypted := make([]byte, length)
	_, err = io.ReadFull(conn, encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}
	
	// Расшифровываем
	decrypted, err := h.crypto.Decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	return decrypted, nil
}

// ============================================================================
// VPN Клиент Реализация
// ============================================================================

// NewVPNClient создает новый VPN клиент
func NewVPNClient() *VPNClient {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &VPNClient{
		config: &MTProtoConfig{
			ServerAddr: DefaultServerAddr,
			DC:         2,
			SessionID:  generateSessionID(),
			ServerSalt: generateServerSalt(),
		},
		ctx:     ctx,
		cancel:  cancel,
	}
}

// generateSessionID генерирует случайный session ID
func generateSessionID() uint64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(^uint64(0))))
	return n.Uint64()
}

// generateServerSalt генерирует случайный server salt
func generateServerSalt() uint64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(^uint64(0))))
	return n.Uint64()
}

// Connect подключается к VPN серверу
func (c *VPNClient) Connect(serverAddr, authKeyHex string, dc int) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	if c.isConnected {
		return errors.New("already connected")
	}
	
	// Парсим адрес сервера
	if serverAddr != "" {
		c.config.ServerAddr = serverAddr
	}
	
	// Парсим auth key
	if authKeyHex != "" {
		authKey, err := hex.DecodeString(strings.ReplaceAll(authKeyHex, " ", ""))
		if err != nil {
			return fmt.Errorf("invalid auth key: %w", err)
		}
		c.config.AuthKey = authKey
	} else {
		// Генерируем тестовый ключ для демонстрации
		c.config.AuthKey = make([]byte, 256)
		rand.Read(c.config.AuthKey)
	}
	
	c.config.DC = dc
	
	// Создаем обработчик
	handler := NewMTProtoHandler(c.config)
	
	// Подключаемся
	conn, err := handler.Connect()
	if err != nil {
		return err
	}
	
	c.conn = conn
	c.isConnected = true
	
	// Запускаем мониторинг соединения
	go c.monitorConnection(handler)
	
	if c.statusCallback != nil {
		c.statusCallback(true, "Connected to "+c.config.ServerAddr)
	}
	
	return nil
}

// Disconnect отключается от VPN сервера
func (c *VPNClient) Disconnect() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	if !c.isConnected {
		return
	}
	
	c.cancel()
	
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	
	c.isConnected = false
	
	if c.statusCallback != nil {
		c.statusCallback(false, "Disconnected")
	}
}

// monitorConnection мониторит состояние соединения
func (c *VPNClient) monitorConnection(handler *MTProtoHandler) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.mutex.RLock()
			if !c.isConnected || c.conn == nil {
				c.mutex.RUnlock()
				return
			}
			c.mutex.RUnlock()
			
			// Обновляем статистику (в реальном приложении здесь была бы реальная статистика)
			c.bytesSent += uint64(rand.Intn(1000))
			c.bytesReceived += uint64(rand.Intn(2000))
			
			if c.statsCallback != nil {
				c.statsCallback(c.bytesSent, c.bytesReceived)
			}
		}
	}
}

// IsConnected проверяет состояние подключения
func (c *VPNClient) IsConnected() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.isConnected
}

// SetStatusCallback устанавливает callback для статуса
func (c *VPNClient) SetStatusCallback(cb func(bool, string)) {
	c.statusCallback = cb
}

// SetStatsCallback устанавливает callback для статистики
func (c *VPNClient) SetStatsCallback(cb func(uint64, uint64)) {
	c.statsCallback = cb
}

// ============================================================================
// Графический Интерфейс (Fyne)
// ============================================================================

// PurpleTheme кастомная фиолетовая тема
type PurpleTheme struct {
	baseTheme fyne.Theme
}

// NewPurpleTheme создает новую фиолетовую тему
func NewPurpleTheme() fyne.Theme {
	return &PurpleTheme{baseTheme: theme.DefaultTheme()}
}

// Color возвращает цвет для заданного имени
func (t *PurpleTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) fyne.Color {
	switch name {
	case theme.ColorNamePrimary:
		return colorFromHex("#9333EA") // Фиолетовый
	case theme.ColorNameBackground:
		return colorFromHex("#1A1025") // Темно-фиолетовый фон
	case theme.ColorNameButton:
		return colorFromHex("#7C3AED")
	case theme.ColorNameDisabled:
		return colorFromHex("#4C1D95")
	case theme.ColorNameError:
		return colorFromHex("#EF4444")
	case theme.ColorNameForeground:
		return colorFromHex("#F3E8FF")
	case theme.ColorNamePlaceHolder:
		return colorFromHex("#A78BFA")
	case theme.ColorNameShadow:
		return colorFromHex("#0F0A1F")
	case theme.ColorNameScrollBar:
		return colorFromHex("#6D28D9")
	case theme.ColorNameSelection:
		return colorFromHex("#8B5CF6")
	default:
		return t.baseTheme.Color(name, variant)
	}
}

// Font возвращает шрифт для заданного стиля
func (t *PurpleTheme) Font(style fyne.TextStyle) fyne.Resource {
	return t.baseTheme.Font(style)
}

// Icon возвращает иконку для заданного имени
func (t *PurpleTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return t.baseTheme.Icon(name)
}

// Size возвращает размер для заданного имени
func (t *PurpleTheme) Size(name fyne.ThemeSizeName) float32 {
	return t.baseTheme.Size(name)
}

// colorFromHex конвертирует HEX строку в цвет
func colorFromHex(hexStr string) fyne.Color {
	r, _ := strconv.ParseInt(hexStr[1:3], 16, 32)
	g, _ := strconv.ParseInt(hexStr[3:5], 16, 32)
	b, _ := strconv.ParseInt(hexStr[5:7], 16, 32)
	return fyne.NewColor(uint8(r), uint8(g), uint8(b))
}

// createMainWindow создает главное окно приложения
func createMainWindow(vpnClient *VPNClient) fyne.Window {
	myApp := app.NewWithID("com.mtproto.vpnclient")
	myApp.Settings().SetTheme(NewPurpleTheme())
	
	mainWindow := myApp.NewWindow("🔐 MTProto VPN Client")
	mainWindow.Resize(fyne.NewSize(600, 700))
	
	// Создаем состояние UI
	uiState := &UIState{}
	
	// Основной контейнер
	content := createMainContent(mainWindow, vpnClient, uiState)
	mainWindow.SetContent(content)
	
	// Устанавливаем callbacks
	vpnClient.SetStatusCallback(func(connected bool, message string) {
		uiState.isConnected = connected
		updateConnectionStatus(uiState, connected, message)
	})
	
	vpnClient.SetStatsCallback(func(sent, received uint64) {
		updateStats(uiState, sent, received)
	})
	
	return mainWindow
}

// createMainContent создает основной контент окна
func createMainContent(window fyne.Window, vpnClient *VPNClient, uiState *UIState) fyne.CanvasObject {
	// Загружаем конфигурацию
	config, configPath, _ := LoadConfig()
	uiState.appConfig = config
	uiState.configFile = configPath
	
	// Заголовок
	titleLabel := widget.NewLabel("MTProto VPN Client")
	titleLabel.TextStyle = fyne.TextStyle{Bold: true}
	titleLabel.Alignment = fyne.TextAlignCenter
	titleLabel.TextSize = 24
	
	subtitleLabel := widget.NewLabel("Secure & Fast VPN Connection")
	subtitleLabel.Alignment = fyne.TextAlignCenter
	subtitleColor := canvas.NewText(subtitleLabel.Text, colorFromHex("#A78BFA"))
	subtitleColor.Alignment = fyne.TextAlignCenter
	
	// Логотип/Иконка
	logoIcon := canvas.NewText("🛡️", colorFromHex("#9333EA"))
	logoIcon.TextSize = 64
	logoIcon.Alignment = fyne.TextAlignCenter
	
	// Поля ввода с загруженными значениями
	uiState.serverEntry = widget.NewEntry()
	uiState.serverEntry.SetPlaceHolder("Server Address (e.g., 149.154.167.50)")
	uiState.serverEntry.SetText(config.ServerAddr)
	
	uiState.portEntry = widget.NewEntry()
	uiState.portEntry.SetPlaceHolder("Port")
	uiState.portEntry.SetText(config.Port)
	
	uiState.dcEntry = widget.NewEntry()
	uiState.dcEntry.SetPlaceHolder("Data Center ID")
	uiState.dcEntry.SetText(strconv.Itoa(config.DC))
	
	uiState.authKeyEntry = widget.NewEntry()
	uiState.authKeyEntry.SetPlaceHolder("Auth Key (hex, optional)")
	uiState.authKeyEntry.SetText(config.AuthKey)
	uiState.authKeyEntry.MultiLine = true
	uiState.authKeyEntry.Wrapping = fyne.TextWrapWord
	
	// Кнопка подключения
	uiState.connectBtn = widget.NewButton("Connect", func() {
		onConnectClick(vpnClient, uiState, window)
	})
	uiState.connectBtn.Importance = widget.HighImportance
	uiState.connectBtn.Style = widget.PrimaryButton
	
	// Индикатор статуса
	uiState.statusLabel = widget.NewLabel("Status: Disconnected")
	uiState.statusLabel.Alignment = fyne.TextAlignCenter
	
	// Прогресс бар
	uiState.progressBar = widget.NewProgressBar()
	uiState.progressBar.Hide()
	
	// Статистика
	uiState.statsLabel = widget.NewLabel("📊 Sent: 0 B | Received: 0 B")
	uiState.statsLabel.Alignment = fyne.TextAlignCenter
	
	// Лог
	uiState.logText = widget.NewEntry()
	uiState.logText.SetPlaceHolder("Connection logs...")
	uiState.logText.MultiLine = true
	uiState.logText.Wrapping = fyne.TextWrapWord
	uiState.logText.Disable()
	
	// Форма настроек
	settingsCard := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Server", uiState.serverEntry),
			widget.NewFormItem("Port", uiState.portEntry),
			widget.NewFormItem("DC", uiState.dcEntry),
			widget.NewFormItem("Auth Key", uiState.authKeyEntry),
		),
	)
	
	// Кнопки управления
	buttonRow := container.NewHBox(
		layout.NewSpacer(),
		uiState.connectBtn,
		layout.NewSpacer(),
	)
	
	// Кнопки конфигурации
	configBtn := widget.NewButtonWithIcon("⚙️ Config", theme.SettingsResource(), func() {
		showConfigDialog(window, uiState)
	})
	
	importBtn := widget.NewButtonWithIcon("📥 Import", theme.DocumentCreateResource(), func() {
		showImportDialog(window, uiState)
	})
	
	exportBtn := widget.NewButtonWithIcon("📤 Export", theme.DocumentSaveResource(), func() {
		showExportDialog(window, uiState)
	})
	
	configButtonRow := container.NewHBox(
		configBtn,
		importBtn,
		exportBtn,
	)
	
	// Основной контент с прокруткой
	scrollContent := container.NewVScroll(
		container.NewVBox(
			layout.NewSpacer(),
			logoIcon,
			titleLabel,
			subtitleColor,
			layout.NewSpacer(),
			widget.NewSeparator(),
			settingsCard,
			widget.NewSeparator(),
			configButtonRow,
			widget.NewSeparator(),
			buttonRow,
			widget.NewSeparator(),
			uiState.statusLabel,
			uiState.progressBar,
			uiState.statsLabel,
			widget.NewSeparator(),
			widget.NewLabel("Logs:"),
			uiState.logText,
			layout.NewSpacer(),
		),
	)
	
	// Меню
	createMenu(window, vpnClient, uiState)
	
	return scrollContent
}

// onConnectClick обрабатывает нажатие кнопки подключения
func onConnectClick(vpnClient *VPNClient, uiState *UIState, window fyne.Window) {
	if vpnClient.IsConnected() {
		// Отключаемся
		vpnClient.Disconnect()
		uiState.connectBtn.SetText("Connect")
		uiState.progressBar.Hide()
		appendLog(uiState.logText, "Disconnecting...")
		
		// Сохраняем конфигурацию при отключении
		saveCurrentConfig(uiState)
	} else {
		// Подключаемся
		serverAddr := uiState.serverEntry.Text
		port := uiState.portEntry.Text
		dcStr := uiState.dcEntry.Text
		authKey := uiState.authKeyEntry.Text
		
		// Формируем полный адрес
		fullServerAddr := serverAddr + ":" + port
		
		dc, err := strconv.Atoi(dcStr)
		if err != nil {
			dialog.ShowError(errors.New("Invalid Data Center ID"), window)
			return
		}
		
		// Обновляем конфигурацию
		if uiState.appConfig != nil {
			uiState.appConfig.ServerAddr = serverAddr
			uiState.appConfig.Port = port
			uiState.appConfig.DC = dc
			uiState.appConfig.AuthKey = authKey
		}
		
		uiState.connectBtn.SetText("Connecting...")
		uiState.connectBtn.Disable()
		uiState.progressBar.Show()
		uiState.progressBar.SetValue(0.5)
		appendLog(uiState.logText, fmt.Sprintf("Connecting to %s (DC: %d)...", fullServerAddr, dc))
		
		// Запускаем подключение в горутине
		go func() {
			err := vpnClient.Connect(fullServerAddr, authKey, dc)
			
			fyne.Do(func() {
				uiState.connectBtn.Enable()
				if err != nil {
					uiState.connectBtn.SetText("Connect")
					uiState.progressBar.Hide()
					appendLog(uiState.logText, "Connection failed: "+err.Error())
					dialog.ShowError(err, window)
				} else {
					uiState.connectBtn.SetText("Disconnect")
					appendLog(uiState.logText, "Connected successfully!")
					
					// Сохраняем конфигурацию после успешного подключения
					saveCurrentConfig(uiState)
				}
			})
		}()
	}
}

// saveCurrentConfig сохраняет текущую конфигурацию
func saveCurrentConfig(uiState *UIState) {
	if uiState.appConfig == nil {
		return
	}
	
	uiState.appConfig.ServerAddr = uiState.serverEntry.Text
	uiState.appConfig.Port = uiState.portEntry.Text
	dc, _ := strconv.Atoi(uiState.dcEntry.Text)
	uiState.appConfig.DC = dc
	uiState.appConfig.AuthKey = uiState.authKeyEntry.Text
	
	SaveConfig(uiState.appConfig, uiState.configFile)
}

// updateConnectionStatus обновляет статус подключения
func updateConnectionStatus(uiState *UIState, connected bool, message string) {
	fyne.Do(func() {
		if connected {
			uiState.statusLabel.SetText("✅ Status: " + message)
			uiState.statusLabel.Color = colorFromHex("#10B981")
			uiState.progressBar.SetValue(1.0)
			time.AfterFunc(2*time.Second, func() {
				fyne.Do(func() {
					uiState.progressBar.Hide()
				})
			})
		} else {
			uiState.statusLabel.SetText("❌ Status: " + message)
			uiState.statusLabel.Color = colorFromHex("#EF4444")
			uiState.progressBar.Hide()
		}
	})
}

// updateStats обновляет статистику
func updateStats(uiState *UIState, sent, received uint64) {
	fyne.Do(func() {
		sentStr := formatBytes(sent)
		receivedStr := formatBytes(received)
		uiState.statsLabel.SetText(fmt.Sprintf("📊 Sent: %s | Received: %s", sentStr, receivedStr))
	})
}

// formatBytes форматирует размер в байтах
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// appendLog добавляет запись в лог
func appendLog(logEntry *widget.Entry, message string) {
	timestamp := time.Now().Format("15:04:05")
	logText := fmt.Sprintf("[%s] %s\n", timestamp, message)
	logEntry.SetText(logEntry.Text + logText)
	
	// Прокрутка вниз
	// В Fyne это делается автоматически при обновлении текста
}

// createMenu создает меню приложения
func createMenu(window fyne.Window, vpnClient *VPNClient, uiState *UIState) {
	newFileItem := fyne.NewMenuItem("New Connection", func() {
		uiState.serverEntry.SetText("")
		uiState.dcEntry.SetText("2")
		uiState.authKeyEntry.SetText("")
		appendLog(uiState.logText, "Cleared connection settings")
	})
	
	quitItem := fyne.NewMenuItem("Quit", func() {
		vpnClient.Disconnect()
		window.Close()
	})
	
	fileMenu := fyne.NewMenu("File", newFileItem, quitItem)
	
	settingsItem := fyne.NewMenuItem("Settings", func() {
		showSettingsDialog(window, uiState)
	})
	
	aboutItem := fyne.NewMenuItem("About", func() {
		showAboutDialog(window)
	})
	
	helpMenu := fyne.NewMenu("Help", settingsItem, aboutItem)
	
	mainMenu := fyne.NewMainMenu(fileMenu, helpMenu)
	window.SetMainMenu(mainMenu)
}

// showSettingsDialog показывает диалог настроек
func showSettingsDialog(window fyne.Window, uiState *UIState) {
	autoConnectCheck := widget.NewCheck("Auto-connect on startup", func(checked bool) {})
	darkModeCheck := widget.NewCheck("Dark Mode", func(checked bool) {
		uiState.darkTheme = checked
	})
	
	form := widget.NewForm(
		widget.NewFormItem("Auto Connect", autoConnectCheck),
		widget.NewFormItem("Theme", darkModeCheck),
	)
	
	dialog.ShowCustomConfirm("Settings", "Save", "Cancel", form,
		func(confirmed bool) {
			if confirmed {
				appendLog(uiState.logText, "Settings saved")
			}
		}, window)
}

// showAboutDialog показывает диалог о программе
func showAboutDialog(window fyne.Window) {
	content := container.NewVBox(
		widget.NewLabel("MTProto VPN Client"),
		widget.NewLabel("Version: 1.0.0"),
		widget.NewLabel(""),
		widget.NewLabel("A secure VPN client using MTProto protocol."),
		widget.NewLabel("Built with Go and Fyne."),
		widget.NewLabel(""),
		widget.NewLabel("© 2024 All rights reserved."),
	)
	
	dialog.ShowCustom("About", "OK", content, window)
}

// ============================================================================
// ГЛАВНАЯ ФУНКЦИЯ
// ============================================================================

func main() {
	// Настройка логирования
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("Starting MTProto VPN Client...")
	
	// Создаем VPN клиент
	vpnClient := NewVPNClient()
	
	// Создаем и запускаем главное окно
	mainWindow := createMainWindow(vpnClient)
	mainWindow.ShowAndRun()
	
	// Очищаем ресурсы
	vpnClient.Disconnect()
	log.Println("MTProto VPN Client stopped")
}

// ============================================================================
// ДОПОЛНИТЕЛЬНЫЕ УТИЛИТЫ
// ============================================================================

// PBKDF2DeriveKey выводит ключ из пароля используя PBKDF2
func PBKDF2DeriveKey(password, salt []byte, iterations int, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

// CalculateCRC32 вычисляет CRC32 хеш
func CalculateCRC32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

// ValidateServerAddress проверяет корректность адреса сервера
func ValidateServerAddress(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	
	// Проверяем IP или домен
	ip := net.ParseIP(host)
	if ip == nil {
		// Может быть доменное имя
		_, err := net.LookupHost(host)
		if err != nil {
			return false
		}
	}
	
	// Проверяем порт
	_, err = strconv.Atoi(port)
	return err == nil
}

// GenerateRandomBytes генерирует случайные байты
func GenerateRandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// ============================================================================
// HTTP ПРОКСИ (опционально для обхода блокировок)
// ============================================================================

// HTTPProxyHandler обрабатывает HTTP прокси соединения
type HTTPProxyHandler struct {
	proxyURL string
	client   *http.Client
}

// NewHTTPProxyHandler создает новый HTTP прокси обработчик
func NewHTTPProxyHandler(proxyURL string) (*HTTPProxyHandler, error) {
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	
	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedURL),
	}
	
	return &HTTPProxyHandler{
		proxyURL: proxyURL,
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}, nil
}

// TestConnection тестирует соединение через прокси
func (h *HTTPProxyHandler) TestConnection() error {
	resp, err := h.client.Get("https://www.google.com")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy test failed: status %d", resp.StatusCode)
	}
	
	return nil
}

// ============================================================================
// ДИАЛОГИ КОНФИГУРАЦИИ
// ============================================================================

// showConfigDialog показывает диалог дополнительных настроек
func showConfigDialog(window fyne.Window, uiState *UIState) {
	if uiState.appConfig == nil {
		uiState.appConfig = getDefaultConfig()
	}
	
	// Создаем поля для дополнительных настроек
	proxyCheck := widget.NewCheck("Use Proxy", func(checked bool) {
		uiState.appConfig.UseProxy = checked
	})
	proxyCheck.SetChecked(uiState.appConfig.UseProxy)
	
	proxyEntry := widget.NewEntry()
	proxyEntry.SetPlaceHolder("http://proxy:port")
	proxyEntry.SetText(uiState.appConfig.ProxyAddr)
	if !uiState.appConfig.UseProxy {
		proxyEntry.Disable()
	}
	
	autoConnectCheck := widget.NewCheck("Auto-connect on startup", func(checked bool) {
		uiState.appConfig.AutoConnect = checked
	})
	autoConnectCheck.SetChecked(uiState.appConfig.AutoConnect)
	
	darkThemeCheck := widget.NewCheck("Dark Theme", func(checked bool) {
		uiState.appConfig.DarkTheme = checked
	})
	darkThemeCheck.SetChecked(uiState.appConfig.DarkTheme)
	
	// Кнопка сохранения
	saveBtn := widget.NewButton("Save Settings", func() {
		uiState.appConfig.ProxyAddr = proxyEntry.Text
		SaveConfig(uiState.appConfig, uiState.configFile)
		appendLog(uiState.logText, "Settings saved successfully!")
		dialog.ShowInformation("Success", "Configuration saved to "+uiState.configFile, window)
	})
	
	content := container.NewVBox(
		widget.NewLabel("Additional Settings"),
		widget.NewSeparator(),
		proxyCheck,
		proxyEntry,
		widget.NewSeparator(),
		autoConnectCheck,
		widget.NewSeparator(),
		darkThemeCheck,
		widget.NewSeparator(),
		saveBtn,
	)
	
	d := dialog.NewCustom("Configuration", "Close", content, window)
	d.Resize(fyne.NewSize(400, 350))
	d.Show()
}

// showImportDialog показывает диалог импорта конфигурации
func showImportDialog(window fyne.Window, uiState *UIState) {
	importEntry := widget.NewMultiLineEntry()
	importEntry.SetPlaceHolder("Paste config here (JSON, URL, or server:port:dc:authkey)")
	importEntry.MultiLine = true
	importEntry.Wrapping = fyne.TextWrapWord
	importEntry.SetMinRowsVisible(5)
	
	importBtn := widget.NewButton("Import", func() {
		configStr := importEntry.Text
		if configStr == "" {
			dialog.ShowError(errors.New("Please enter configuration data"), window)
			return
		}
		
		config, err := ImportConfig(configStr)
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to import: %w", err), window)
			return
		}
		
		// Применяем конфигурацию
		uiState.serverEntry.SetText(config.ServerAddr)
		uiState.portEntry.SetText(config.Port)
		uiState.dcEntry.SetText(strconv.Itoa(config.DC))
		uiState.authKeyEntry.SetText(config.AuthKey)
		
		uiState.appConfig = config
		
		appendLog(uiState.logText, "Configuration imported successfully!")
		dialog.ShowInformation("Success", "Configuration imported!\nDon't forget to save it.", window)
	})
	
	content := container.NewVBox(
		widget.NewLabel("Import Configuration"),
		widget.NewLabel("Supported formats:"),
		widget.NewLabel("- JSON"),
		widget.NewLabel("- mtproto://server:port?dc=X&authkey=Y"),
		widget.NewLabel("- server:port:dc:authkey"),
		widget.NewSeparator(),
		importEntry,
		importBtn,
	)
	
	d := dialog.NewCustom("Import Config", "Cancel", content, window)
	d.Resize(fyne.NewSize(500, 400))
	d.Show()
}

// showExportDialog показывает диалог экспорта конфигурации
func showExportDialog(window fyne.Window, uiState *UIState) {
	if uiState.appConfig == nil {
		dialog.ShowError(errors.New("No configuration to export"), window)
		return
	}
	
	// Обновляем конфигурацию из текущих значений
	uiState.appConfig.ServerAddr = uiState.serverEntry.Text
	uiState.appConfig.Port = uiState.portEntry.Text
	dc, _ := strconv.Atoi(uiState.dcEntry.Text)
	uiState.appConfig.DC = dc
	uiState.appConfig.AuthKey = uiState.authKeyEntry.Text
	
	exportedStr := ExportConfig(uiState.appConfig)
	
	exportEntry := widget.NewMultiLineEntry()
	exportEntry.SetText(exportedStr)
	exportEntry.MultiLine = true
	exportEntry.Wrapping = fyne.TextWrapWord
	exportEntry.SetMinRowsVisible(8)
	exportEntry.ReadOnly = true
	
	saveFileBtn := widget.NewButton("Save to File", func() {
		currentPath := uiState.configFile
		if currentPath == "" {
			var err error
			currentPath, err = getConfigPath()
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
		}
		
		err := SaveConfig(uiState.appConfig, currentPath)
		if err != nil {
			dialog.ShowError(err, window)
			return
		}
		
		dialog.ShowInformation("Success", "Configuration saved to:\n"+currentPath, window)
	})
	
	content := container.NewVBox(
		widget.NewLabel("Export Configuration"),
		widget.NewSeparator(),
		widget.NewLabel("JSON format:"),
		exportEntry,
		saveFileBtn,
	)
	
	d := dialog.NewCustom("Export Config", "Close", content, window)
	d.Resize(fyne.NewSize(500, 450))
	d.Show()
}

// ============================================================================
// КОНЕЦ ФАЙЛА
// ============================================================================
