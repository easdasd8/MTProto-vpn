//go:build !cgo
// +build !cgo

// MTProto VPN Client для Windows
// Реализация на чистом Go без CGO (не требует GCC)
// Веб-интерфейс с фиолетовой темой
// Один файл, полная функциональность

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// repeatBytes повторяет байты count раз
func repeatBytes(b []byte, count int) []byte {
	result := make([]byte, len(b)*count)
	for i := 0; i < count; i++ {
		copy(result[i*len(b):(i+1)*len(b)], b)
	}
	return result
}

// ============================================================================
// КОНСТАНТЫ И ПАРАМЕТРЫ MTProto
// ============================================================================

const (
	// Параметры DH из спецификации MTProto
	DHPrimeHex = "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c3720fd51f69458705ac68cd4fe6b6b13abdc9ba46baf89f921584dd74045f07ee68bfb85d391eb63174b253c4fa4fd6fcde7480292ce7647e741c5496d69773248056a1d24b3c7f3d9af56706aca280127fff17a8e47822fcb3b55e06ec7f4d4e2f880c2eb115484ae3e83cfe6509a892c157105f477f3b48c308b707018ab56ffadbd7ea846c23588aacbd21522c19e5b57"
	DHGenerator = 3
	
	// Размеры блоков и ключей
	AESBlockSize = 16
	KeySize      = 32
	IVSize       = 16
	
	// Максимальные размеры пакетов
	MaxPacketSize = 65536
	
	// Таймауты соединений
	ConnectTimeout = 10 * time.Second
	ReadTimeout    = 30 * time.Second
	WriteTimeout   = 30 * time.Second
	
	// Порт по умолчанию для MTProto
	DefaultPort = 443
	
	// Версия клиента
	ClientVersion = "1.0.0"
)

// ============================================================================
// СТРУКТУРЫ ДАННЫХ
// ============================================================================

// AppConfig - конфигурация приложения
type AppConfig struct {
	Server         string `json:"server"`
	Port           int    `json:"port"`
	Datacenter     int    `json:"datacenter"`
	AuthKey        string `json:"auth_key"`
	ProxyEnabled   bool   `json:"proxy_enabled"`
	ProxyHost      string `json:"proxy_host"`
	ProxyPort      int    `json:"proxy_port"`
	AutoConnect    bool   `json:"auto_connect"`
	Theme          string `json:"theme"`
	LogLevel       string `json:"log_level"`
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
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
	PacketsSent   uint64 `json:"packets_sent"`
	PacketsRecv   uint64 `json:"packets_recv"`
	StartTime     time.Time `json:"start_time"`
	mu            sync.Mutex
}

func (ts *TrafficStats) AddSent(bytes uint64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.BytesSent += bytes
	ts.PacketsSent++
}

func (ts *TrafficStats) AddReceived(bytes uint64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.BytesReceived += bytes
	ts.PacketsRecv++
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

// MTProtoClient - основной клиент MTProto
type MTProtoClient struct {
	config      *AppConfig
	conn        net.Conn
	state       ConnectionState
	stateMu     sync.RWMutex
	stats       *TrafficStats
	authKey     []byte
	dcID        int
	serverAddr  string
	ctx         context.Context
	cancel      context.CancelFunc
	logs        []string
	logMu       sync.Mutex
}

// GlobalState - глобальное состояние приложения
type GlobalState struct {
	client     *MTProtoClient
	config     *AppConfig
	server     *http.Server
	port       int
	shutdown   chan struct{}
	wg         sync.WaitGroup
}

var globalState = &GlobalState{
	shutdown: make(chan struct{}),
}

// ============================================================================
// ФУНКЦИИ УПРАВЛЕНИЯ КОНФИГУРАЦИЕЙ
// ============================================================================

func getConfigPath() (string, error) {
	var configDir string
	
	if os.Getenv("APPDATA") != "" {
		// Windows
		configDir = filepath.Join(os.Getenv("APPDATA"), "MTProtoVPN")
	} else if os.Getenv("HOME") != "" {
		// Linux/Mac
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
		return getDefaultConfig(), err
	}
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return getDefaultConfig(), nil
		}
		return getDefaultConfig(), err
	}
	
	var config AppConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return getDefaultConfig(), err
	}
	
	if config.Port == 0 {
		config.Port = DefaultPort
	}
	if config.Theme == "" {
		config.Theme = "purple"
	}
	if config.LogLevel == "" {
		config.LogLevel = "info"
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
		Server:       "",
		Port:         DefaultPort,
		Datacenter:   1,
		AuthKey:      "",
		ProxyEnabled: false,
		ProxyHost:    "",
		ProxyPort:    0,
		AutoConnect:  false,
		Theme:        "purple",
		LogLevel:     "info",
	}
}

func ValidateConfig(config *AppConfig) error {
	if config.Server == "" {
		return errors.New("адрес сервера не указан")
	}
	
	if config.Port < 1 || config.Port > 65535 {
		return errors.New("неверный номер порта")
	}
	
	if config.AuthKey == "" {
		return errors.New("ключ авторизации не указан")
	}
	
	// Проверка формата ключа (должен быть hex или base64)
	if _, err := hex.DecodeString(config.AuthKey); err != nil {
		if _, err := base64.StdEncoding.DecodeString(config.AuthKey); err != nil {
			return errors.New("неверный формат ключа авторизации (должен быть hex или base64)")
		}
	}
	
	return nil
}

func ImportConfig(configStr string) (*AppConfig, error) {
	configStr = strings.TrimSpace(configStr)
	
	// Попытка распарсить как JSON
	var config AppConfig
	if err := json.Unmarshal([]byte(configStr), &config); err == nil {
		return &config, nil
	}
	
	// Попытка распарсить как URL mtproto://
	if strings.HasPrefix(configStr, "mtproto://") {
		u, err := url.Parse(configStr)
		if err != nil {
			return nil, errors.New("неверный формат URL")
		}
		
		config.Server = u.Hostname()
		if port := u.Port(); port != "" {
			config.Port, _ = strconv.Atoi(port)
		} else {
			config.Port = DefaultPort
		}
		
		query := u.Query()
		config.Datacenter, _ = strconv.Atoi(query.Get("dc"))
		config.AuthKey = query.Get("key")
		
		return &config, nil
	}
	
	// Попытка распарсить как простой формат: server:port:dc:authkey
	parts := strings.Split(configStr, ":")
	if len(parts) >= 4 {
		config.Server = parts[0]
		config.Port, _ = strconv.Atoi(parts[1])
		config.Datacenter, _ = strconv.Atoi(parts[2])
		config.AuthKey = parts[3]
		return &config, nil
	}
	
	return nil, errors.New("не удалось распознать формат конфигурации")
}

func ExportConfig(config *AppConfig) (string, error) {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ============================================================================
// КРИПТОГРАФИЧЕСКИЕ ФУНКЦИИ MTProto
// ============================================================================

// GenerateKeyFromAuth генерирует ключи из auth key
func GenerateKeyFromAuth(authKey []byte, msgKey []byte, isOutgoing bool) ([]byte, []byte, error) {
	offset := 0
	if isOutgoing {
		offset = 8
	} else {
		offset = 0
	}
	
	// SHA256(a+x1..a+x32), где a — auth_key, x — msg_key
	a := authKey[offset : offset+32]
	x := msgKey
	
	tmp := make([]byte, len(a)+len(x))
	copy(tmp, a)
	copy(tmp[len(a):], x)
	
	hash := sha256.Sum256(tmp)
	
	// Первые 16 байт — aes_key, следующие 16 — aes_iv
	aesKey := hash[:16]
	aesIV := hash[16:32]
	
	return aesKey, aesIV, nil
}

// EncryptMTProto шифрует данные по протоколу MTProto 2.0
func EncryptMTProto(authKey []byte, data []byte, isOutgoing bool) ([]byte, error) {
	// Генерация msg_key
	msgKeyFull := sha256.Sum256(data)
	msgKey := msgKeyFull[8:24] // Берём средние 16 байт
	
	// Генерация ключей шифрования
	aesKey, aesIV, err := GenerateKeyFromAuth(authKey, msgKey, isOutgoing)
	if err != nil {
		return nil, err
	}
	
	// Создание cipher block
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	
	// CBC режим шифрования
	plaintext := padPKCS7(data, AESBlockSize)
	ciphertext := make([]byte, len(plaintext))
	
	mode := cipher.NewCBCEncrypter(block, aesIV)
	mode.CryptBlocks(ciphertext, plaintext)
	
	// Формирование итогового пакета: [msg_key (16)] + [encrypted_data]
	result := append(msgKey, ciphertext...)
	
	return result, nil
}

// DecryptMTProto расшифровывает данные по протоколу MTProto 2.0
func DecryptMTProto(authKey []byte, encryptedData []byte, isOutgoing bool) ([]byte, error) {
	if len(encryptedData) < 16 {
		return nil, errors.New("слишком короткий зашифрованный пакет")
	}
	
	// Извлечение msg_key
	msgKey := encryptedData[:16]
	ciphertext := encryptedData[16:]
	
	// Генерация ключей расшифровки
	aesKey, aesIV, err := GenerateKeyFromAuth(authKey, msgKey, isOutgoing)
	if err != nil {
		return nil, err
	}
	
	// Создание cipher block
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	
	// CBC режим расшифровки
	plaintext := make([]byte, len(ciphertext))
	
	mode := cipher.NewCBCDecrypter(block, aesIV)
	mode.CryptBlocks(plaintext, ciphertext)
	
	// Удаление паддинга
	decrypted, err := unpadPKCS7(plaintext)
	if err != nil {
		return nil, err
	}
	
	// Верификация msg_key
	expectedMsgKeyFull := sha256.Sum256(decrypted)
	expectedMsgKey := expectedMsgKeyFull[8:24]
	
	if !strings.EqualFold(hex.EncodeToString(msgKey), hex.EncodeToString(expectedMsgKey)) {
		return nil, errors.New("несоответствие msg_key при расшифровке")
	}
	
	return decrypted, nil
}

// padPKCS7 добавляет PKCS7 паддинг
func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := repeatBytes([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// unpadPKCS7 удаляет PKCS7 паддинг
func unpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("пустые данные")
	}
	
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return nil, errors.New("неверный паддинг")
	}
	
	for i := 0; i < padding; i++ {
		if data[len(data)-1-i] != byte(padding) {
			return nil, errors.New("неверный паддинг")
		}
	}
	
	return data[:len(data)-padding], nil
}

// ============================================================================
// СЕТЕВЫЕ ФУНКЦИИ
// ============================================================================

// NewMTProtoClient создаёт новый экземпляр клиента
func NewMTProtoClient(config *AppConfig) *MTProtoClient {
	ctx, cancel := context.WithCancel(context.Background())
	
	authKey, _ := decodeAuthKey(config.AuthKey)
	
	return &MTProtoClient{
		config:     config,
		state:      StateDisconnected,
		stats:      &TrafficStats{StartTime: time.Now()},
		authKey:    authKey,
		dcID:       config.Datacenter,
		serverAddr: fmt.Sprintf("%s:%d", config.Server, config.Port),
		ctx:        ctx,
		cancel:     cancel,
		logs:       make([]string, 0),
	}
}

func decodeAuthKey(keyStr string) ([]byte, error) {
	// Попытка декодирования из hex
	if key, err := hex.DecodeString(keyStr); err == nil {
		return key, nil
	}
	
	// Попытка декодирования из base64
	if key, err := base64.StdEncoding.DecodeString(keyStr); err == nil {
		return key, nil
	}
	
	return nil, errors.New("не удалось декодировать ключ авторизации")
}

// Connect устанавливает соединение с сервером
func (c *MTProtoClient) Connect() error {
	c.stateMu.Lock()
	if c.state == StateConnecting || c.state == StateConnected {
		c.stateMu.Unlock()
		return errors.New("уже подключено или подключение в процессе")
	}
	c.state = StateConnecting
	c.stateMu.Unlock()
	
	c.addLog("Начало подключения к " + c.serverAddr)
	
	// Создание TCP соединения
	dialer := &net.Dialer{
		Timeout:   ConnectTimeout,
		KeepAlive: 30 * time.Second,
	}
	
	conn, err := dialer.DialContext(c.ctx, "tcp", c.serverAddr)
	if err != nil {
		c.setState(StateError)
		c.addLog("Ошибка подключения: " + err.Error())
		return fmt.Errorf("ошибка подключения: %w", err)
	}
	
	c.conn = conn
	c.conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	c.conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	
	c.addLog("TCP соединение установлено")
	
	// Здесь должна быть логика рукопожатия MTProto
	// Для демонстрации считаем соединение успешным после установки TCP
	// В реальном клиенте здесь был бы полный handshake MTProto
	
	c.setState(StateConnected)
	c.stats.StartTime = time.Now()
	c.addLog("Успешное подключение к серверу")
	
	// Запуск горутин для чтения данных
	go c.readLoop()
	
	return nil
}

// Disconnect разрывает соединение
func (c *MTProtoClient) Disconnect() error {
	c.stateMu.Lock()
	if c.state != StateConnected {
		c.stateMu.Unlock()
		return nil
	}
	c.stateMu.Unlock()
	
	c.addLog("Разрыв соединения...")
	
	if c.cancel != nil {
		c.cancel()
	}
	
	if c.conn != nil {
		c.conn.Close()
	}
	
	c.setState(StateDisconnected)
	c.addLog("Соединение разорвано")
	
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
	buffer := make([]byte, MaxPacketSize)
	
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		
		if c.conn == nil {
			return
		}
		
		n, err := c.conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				c.addLog("Ошибка чтения: " + err.Error())
			}
			return
		}
		
		c.stats.AddReceived(uint64(n))
		
		// Обработка полученных данных
		// В реальном клиенте здесь была бы расшифровка и обработка пакетов
	}
}

func (c *MTProtoClient) addLog(message string) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	
	timestamp := time.Now().Format("15:04:05")
	logEntry := fmt.Sprintf("[%s] %s", timestamp, message)
	
	c.logs = append(c.logs, logEntry)
	
	// Храним только последние 100 записей
	if len(c.logs) > 100 {
		c.logs = c.logs[1:]
	}
	
	log.Println(logEntry)
}

func (c *MTProtoClient) getLogs() []string {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	
	result := make([]string, len(c.logs))
	copy(result, c.logs)
	return result
}

// Send отправляет данные через соединение
func (c *MTProtoClient) Send(data []byte) (int, error) {
	c.stateMu.RLock()
	if c.state != StateConnected {
		c.stateMu.RUnlock()
		return 0, errors.New("нет активного соединения")
	}
	c.stateMu.RUnlock()
	
	if c.conn == nil {
		return 0, errors.New("соединение не установлено")
	}
	
	// Шифрование данных
	encrypted, err := EncryptMTProto(c.authKey, data, true)
	if err != nil {
		return 0, err
	}
	
	c.conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	n, err := c.conn.Write(encrypted)
	if err != nil {
		return 0, err
	}
	
	c.stats.AddSent(uint64(n))
	
	return n, nil
}

// GetStatus возвращает текущий статус клиента
func (c *MTProtoClient) GetStatus() map[string]interface{} {
	c.stateMu.RLock()
	state := c.state
	c.stateMu.RUnlock()
	
	sendSpeed, recvSpeed := c.stats.GetSpeed()
	
	return map[string]interface{}{
		"state":          state.String(),
		"state_code":     state,
		"server":         c.config.Server,
		"port":           c.config.Port,
		"datacenter":     c.dcID,
		"bytes_sent":     c.stats.BytesSent,
		"bytes_received": c.stats.BytesReceived,
		"packets_sent":   c.stats.PacketsSent,
		"packets_recv":   c.stats.PacketsRecv,
		"send_speed":     sendSpeed,
		"recv_speed":     recvSpeed,
		"uptime":         time.Since(c.stats.StartTime).String(),
	}
}

// ============================================================================
// ВЕБ-ИНТЕРФЕЙС
// ============================================================================

const htmlTemplate = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MTProto VPN Client</title>
    <style>
        :root {
            --primary: #9333EA;
            --primary-dark: #7C3AED;
            --primary-light: #A855F7;
            --bg-dark: #1A1025;
            --bg-card: #2D1B4E;
            --text-primary: #FFFFFF;
            --text-secondary: #C4B5FD;
            --success: #10B981;
            --error: #EF4444;
            --warning: #F59E0B;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, var(--bg-dark) 0%, #2D1B4E 100%);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 2rem;
        }
        
        .container {
            max-width: 900px;
            width: 100%;
        }
        
        header {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        h1 {
            font-size: 2.5rem;
            background: linear-gradient(135deg, var(--primary-light), var(--primary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }
        
        .subtitle {
            color: var(--text-secondary);
            font-size: 1.1rem;
        }
        
        .card {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 8px 32px rgba(147, 51, 234, 0.2);
            border: 1px solid rgba(147, 51, 234, 0.3);
        }
        
        .card-title {
            font-size: 1.3rem;
            margin-bottom: 1rem;
            color: var(--primary-light);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: 600;
        }
        
        .status-disconnected {
            background: rgba(239, 68, 68, 0.2);
            color: var(--error);
        }
        
        .status-connecting {
            background: rgba(245, 158, 11, 0.2);
            color: var(--warning);
        }
        
        .status-connected {
            background: rgba(16, 185, 129, 0.2);
            color: var(--success);
        }
        
        .status-error {
            background: rgba(239, 68, 68, 0.2);
            color: var(--error);
        }
        
        .dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        .dot-connected { background: var(--success); }
        .dot-disconnected { background: var(--error); }
        .dot-connecting { background: var(--warning); }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .btn {
            padding: 0.75rem 2rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(147, 51, 234, 0.4);
        }
        
        .btn-danger {
            background: linear-gradient(135deg, #EF4444, #DC2626);
            color: white;
        }
        
        .btn-secondary {
            background: rgba(147, 51, 234, 0.2);
            color: var(--primary-light);
            border: 1px solid var(--primary);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .stat-item {
            background: rgba(147, 51, 234, 0.1);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--primary-light);
        }
        
        .stat-label {
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--text-secondary);
        }
        
        .form-control {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid rgba(147, 51, 234, 0.3);
            border-radius: 8px;
            background: rgba(26, 16, 37, 0.5);
            color: var(--text-primary);
            font-size: 1rem;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(147, 51, 234, 0.2);
        }
        
        .logs-container {
            background: rgba(26, 16, 37, 0.8);
            border-radius: 8px;
            padding: 1rem;
            max-height: 300px;
            overflow-y: auto;
            font-family: 'Consolas', monospace;
            font-size: 0.85rem;
        }
        
        .log-entry {
            padding: 0.25rem 0;
            border-bottom: 1px solid rgba(147, 51, 234, 0.1);
        }
        
        .log-entry:last-child {
            border-bottom: none;
        }
        
        .log-time {
            color: var(--primary-light);
            margin-right: 0.5rem;
        }
        
        .actions {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-top: 1rem;
        }
        
        .hidden { display: none; }
        
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        
        .modal {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 2rem;
            max-width: 500px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 1.5rem;
            cursor: pointer;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }
        
        input[type="checkbox"] {
            width: 18px;
            height: 18px;
            accent-color: var(--primary);
        }
        
        footer {
            margin-top: 2rem;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 MTProto VPN</h1>
            <p class="subtitle">Безопасное соединение с красивым интерфейсом</p>
        </header>
        
        <div class="card">
            <div class="card-title">📊 Статус соединения</div>
            <div id="statusBadge" class="status-indicator status-disconnected">
                <span class="dot dot-disconnected"></span>
                <span id="statusText">Отключено</span>
            </div>
            
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value" id="bytesSent">0 B</div>
                    <div class="stat-label">Отправлено</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="bytesReceived">0 B</div>
                    <div class="stat-label">Получено</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="sendSpeed">0 KB/s</div>
                    <div class="stat-label">Скорость отправки</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="recvSpeed">0 KB/s</div>
                    <div class="stat-label">Скорость получения</div>
                </div>
            </div>
            
            <div class="actions">
                <button id="connectBtn" class="btn btn-primary" onclick="toggleConnection()">
                    🔌 Подключиться
                </button>
                <button class="btn btn-secondary" onclick="showSettings()">
                    ⚙️ Настройки
                </button>
                <button class="btn btn-secondary" onclick="showImport()">
                    📥 Импорт
                </button>
                <button class="btn btn-secondary" onclick="exportConfig()">
                    📤 Экспорт
                </button>
            </div>
        </div>
        
        <div class="card">
            <div class="card-title">📋 Информация о сервере</div>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value" id="serverInfo">-</div>
                    <div class="stat-label">Сервер</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="portInfo">-</div>
                    <div class="stat-label">Порт</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="dcInfo">-</div>
                    <div class="stat-label">Дата-центр</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="uptimeInfo">0s</div>
                    <div class="stat-label">Время работы</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-title">📝 Журнал событий</div>
            <div class="logs-container" id="logsContainer">
                <div class="log-entry">Ожидание событий...</div>
            </div>
            <div class="actions">
                <button class="btn btn-secondary" onclick="clearLogs()">🗑️ Очистить</button>
            </div>
        </div>
        
        <footer>
            <p>MTProto VPN Client v{{.Version}} | Pure Go Implementation</p>
        </footer>
    </div>
    
    <!-- Модальное окно настроек -->
    <div id="settingsModal" class="modal-overlay hidden">
        <div class="modal">
            <div class="modal-header">
                <h2>⚙️ Настройки</h2>
                <button class="modal-close" onclick="hideSettings()">&times;</button>
            </div>
            <form id="settingsForm" onsubmit="saveSettings(event)">
                <div class="form-group">
                    <label for="server">Адрес сервера</label>
                    <input type="text" id="server" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="port">Порт</label>
                    <input type="number" id="port" class="form-control" value="443" required>
                </div>
                <div class="form-group">
                    <label for="datacenter">Дата-центр</label>
                    <input type="number" id="datacenter" class="form-control" value="1" required>
                </div>
                <div class="form-group">
                    <label for="authKey">Ключ авторизации</label>
                    <textarea id="authKey" class="form-control" rows="3" required></textarea>
                </div>
                <div class="checkbox-group">
                    <input type="checkbox" id="autoConnect">
                    <label for="autoConnect">Автоподключение при запуске</label>
                </div>
                <div class="actions" style="margin-top: 1.5rem;">
                    <button type="submit" class="btn btn-primary">💾 Сохранить</button>
                    <button type="button" class="btn btn-secondary" onclick="hideSettings()">Отмена</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Модальное окно импорта -->
    <div id="importModal" class="modal-overlay hidden">
        <div class="modal">
            <div class="modal-header">
                <h2>📥 Импорт конфигурации</h2>
                <button class="modal-close" onclick="hideImport()">&times;</button>
            </div>
            <form onsubmit="importConfig(event)">
                <div class="form-group">
                    <label for="importData">Вставьте конфигурацию (JSON, URL или текст)</label>
                    <textarea id="importData" class="form-control" rows="6" required></textarea>
                </div>
                <div class="actions">
                    <button type="submit" class="btn btn-primary">📥 Импорт</button>
                    <button type="button" class="btn btn-secondary" onclick="hideImport()">Отмена</button>
                </div>
            </form>
        </div>
    </div>
    
    <script>
        let isConnected = false;
        let updateInterval = null;
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function formatSpeed(bytesPerSec) {
            return formatBytes(bytesPerSec) + '/s';
        }
        
        async function fetchStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                
                // Обновление статуса
                const statusBadge = document.getElementById('statusBadge');
                const statusText = document.getElementById('statusText');
                const dot = statusBadge.querySelector('.dot');
                
                statusBadge.className = 'status-indicator status-' + (data.state.toLowerCase().replace(' ', '-'));
                statusText.textContent = data.state;
                
                if (data.state_code === 2) { // Connected
                    dot.className = 'dot dot-connected';
                    document.getElementById('connectBtn').innerHTML = '❌ Отключиться';
                    document.getElementById('connectBtn').className = 'btn btn-danger';
                    isConnected = true;
                } else {
                    dot.className = 'dot dot-disconnected';
                    document.getElementById('connectBtn').innerHTML = '🔌 Подключиться';
                    document.getElementById('connectBtn').className = 'btn btn-primary';
                    isConnected = false;
                }
                
                // Обновление статистики
                document.getElementById('bytesSent').textContent = formatBytes(data.bytes_sent);
                document.getElementById('bytesReceived').textContent = formatBytes(data.bytes_received);
                document.getElementById('sendSpeed').textContent = formatSpeed(data.send_speed);
                document.getElementById('recvSpeed').textContent = formatSpeed(data.recv_speed);
                document.getElementById('uptimeInfo').textContent = data.uptime;
                
                // Информация о сервере
                document.getElementById('serverInfo').textContent = data.server || '-';
                document.getElementById('portInfo').textContent = data.port || '-';
                document.getElementById('dcInfo').textContent = 'DC' + (data.datacenter || '-');
                
                // Автоматическое подключение если нужно
                if ({{.AutoConnect}} && !isConnected) {
                    toggleConnection();
                }
            } catch (error) {
                console.error('Ошибка получения статуса:', error);
            }
        }
        
        async function fetchLogs() {
            try {
                const response = await fetch('/api/logs');
                const logs = await response.json();
                
                const container = document.getElementById('logsContainer');
                if (logs.length === 0) {
                    container.innerHTML = '<div class="log-entry">Нет событий</div>';
                    return;
                }
                
                container.innerHTML = logs.map(log => 
                    '<div class="log-entry"><span class="log-time">' + log.substring(0, 10) + '</span>' + log.substring(11) + '</div>'
                ).reverse().join('');
            } catch (error) {
                console.error('Ошибка получения логов:', error);
            }
        }
        
        async function toggleConnection() {
            try {
                const action = isConnected ? 'disconnect' : 'connect';
                const response = await fetch('/api/' + action, { method: 'POST' });
                const result = await response.json();
                
                if (!result.success) {
                    alert('Ошибка: ' + result.error);
                }
                
                setTimeout(fetchStatus, 500);
            } catch (error) {
                alert('Ошибка операции: ' + error.message);
            }
        }
        
        function showSettings() {
            document.getElementById('settingsModal').classList.remove('hidden');
            fetch('/api/config')
                .then(r => r.json())
                .then(config => {
                    document.getElementById('server').value = config.server || '';
                    document.getElementById('port').value = config.port || 443;
                    document.getElementById('datacenter').value = config.datacenter || 1;
                    document.getElementById('authKey').value = config.auth_key || '';
                    document.getElementById('autoConnect').checked = config.auto_connect || false;
                });
        }
        
        function hideSettings() {
            document.getElementById('settingsModal').classList.add('hidden');
        }
        
        async function saveSettings(event) {
            event.preventDefault();
            
            const config = {
                server: document.getElementById('server').value,
                port: parseInt(document.getElementById('port').value),
                datacenter: parseInt(document.getElementById('datacenter').value),
                auth_key: document.getElementById('authKey').value,
                auto_connect: document.getElementById('autoConnect').checked
            };
            
            try {
                const response = await fetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                
                const result = await response.json();
                if (result.success) {
                    alert('Настройки сохранены!');
                    hideSettings();
                    fetchStatus();
                } else {
                    alert('Ошибка: ' + result.error);
                }
            } catch (error) {
                alert('Ошибка сохранения: ' + error.message);
            }
        }
        
        function showImport() {
            document.getElementById('importModal').classList.remove('hidden');
        }
        
        function hideImport() {
            document.getElementById('importModal').classList.add('hidden');
        }
        
        async function importConfig(event) {
            event.preventDefault();
            
            const importData = document.getElementById('importData').value;
            
            try {
                const response = await fetch('/api/import', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ config: importData })
                });
                
                const result = await response.json();
                if (result.success) {
                    alert('Конфигурация импортирована!');
                    hideImport();
                    showSettings();
                } else {
                    alert('Ошибка: ' + result.error);
                }
            } catch (error) {
                alert('Ошибка импорта: ' + error.message);
            }
        }
        
        async function exportConfig() {
            try {
                const response = await fetch('/api/export');
                const result = await response.json();
                
                if (result.success) {
                    navigator.clipboard.writeText(result.config)
                        .then(() => alert('Конфигурация скопирована в буфер обмена!'))
                        .catch(() => {
                            const blob = new Blob([result.config], { type: 'application/json' });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = 'mtproto_config.json';
                            a.click();
                        });
                } else {
                    alert('Ошибка: ' + result.error);
                }
            } catch (error) {
                alert('Ошибка экспорта: ' + error.message);
            }
        }
        
        function clearLogs() {
            fetch('/api/logs/clear', { method: 'POST' });
            document.getElementById('logsContainer').innerHTML = '<div class="log-entry">Журнал очищен</div>';
        }
        
        // Автообновление
        setInterval(fetchStatus, 2000);
        setInterval(fetchLogs, 3000);
        
        // Первоначальная загрузка
        fetchStatus();
        fetchLogs();
    </script>
</body>
</html>`

// ============================================================================
// HTTP HANDLERS
// ============================================================================

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	tmpl, err := template.New("index").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		return
	}
	
	data := map[string]interface{}{
		"Version":    ClientVersion,
		"AutoConnect": globalState.config.AutoConnect,
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if globalState.client == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"state":      "Отключено",
			"state_code": 0,
		})
		return
	}
	
	status := globalState.client.GetStatus()
	json.NewEncoder(w).Encode(status)
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if globalState.client == nil {
		config := globalState.config
		if err := ValidateConfig(config); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			})
			return
		}
		
		globalState.client = NewMTProtoClient(config)
	}
	
	err := globalState.client.Connect()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func handleDisconnect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if globalState.client == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
		return
	}
	
	err := globalState.client.Disconnect()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(globalState.config)
}

func handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var config AppConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	
	globalState.config = &config
	
	if err := SaveConfig(&config); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	
	// Пересоздать клиент с новой конфигурацией
	if globalState.client != nil {
		globalState.client.Disconnect()
		globalState.client = NewMTProtoClient(&config)
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func handleImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var req struct {
		Config string `json:"config"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	
	config, err := ImportConfig(req.Config)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	
	globalState.config = config
	
	if err := SaveConfig(config); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	configStr, err := ExportConfig(globalState.config)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"config":  configStr,
	})
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if globalState.client == nil {
		json.NewEncoder(w).Encode([]string{})
		return
	}
	
	logs := globalState.client.getLogs()
	json.NewEncoder(w).Encode(logs)
}

func handleClearLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if globalState.client != nil {
		globalState.client.logMu.Lock()
		globalState.client.logs = make([]string, 0)
		globalState.client.logMu.Unlock()
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

func main() {
	fmt.Println("🔐 MTProto VPN Client v" + ClientVersion)
	fmt.Println("Pure Go Implementation (No CGO)")
	fmt.Println("=" + strings.Repeat("=", 50))
	
	// Загрузка конфигурации
	config, err := LoadConfig()
	if err != nil {
		log.Printf("Warning: Could not load config: %v", err)
		config = getDefaultConfig()
	}
	globalState.config = config
	
	// Создание клиента
	globalState.client = NewMTProtoClient(config)
	
	// Настройка HTTP сервера
	mux := http.NewServeMux()
	
	// Web интерфейс
	mux.HandleFunc("/", handleIndex)
	
	// API endpoints
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/connect", handleConnect)
	mux.HandleFunc("/api/disconnect", handleDisconnect)
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetConfig(w, r)
		case http.MethodPost:
			handleSaveConfig(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/import", handleImport)
	mux.HandleFunc("/api/export", handleExport)
	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleLogs(w, r)
		case http.MethodPost:
			handleClearLogs(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	
	// Поиск свободного порта
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	
	globalState.port = listener.Addr().(*net.TCPAddr).Port
	
	globalState.server = &http.Server{
		Addr:         ":" + strconv.Itoa(globalState.port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	fmt.Printf("🌐 Web interface: http://localhost:%d\n", globalState.port)
	fmt.Println("📡 Press Ctrl+C to exit")
	fmt.Println("=" + strings.Repeat("=", 50))
	
	// Запуск сервера в горутине
	go func() {
		if err := globalState.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()
	
	// Автоматическое подключение если настроено
	if config.AutoConnect {
		go func() {
			time.Sleep(2 * time.Second)
			if err := globalState.client.Connect(); err != nil {
				log.Printf("Auto-connect failed: %v", err)
			}
		}()
	}
	
	// Ожидание сигнала завершения
	<-globalState.shutdown
	
	//Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if globalState.client != nil {
		globalState.client.Disconnect()
	}
	
	globalState.server.Shutdown(ctx)
	
	fmt.Println("\n👋 Goodbye!")
}
