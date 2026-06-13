package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	maxLogSize    = 50 * 1024 * 1024 // 50MB
	maxLogBackups = 3
)

const Version = "1.0.1"

type AppConfig struct {
	Debug                  bool
	LogLevel               string
	RetentionDays          int
	RetentionIntervalHours int
	logger                 *log.Logger
	logFile                *os.File
	logPath                string
	logSize                int64
	mu                     sync.RWMutex

	// debugFlag mirrors Debug for lock-free reads on the hot path.
	// LogDebug is called dozens of times per request; reading it via the
	// RWMutex would add avoidable atomic contention under high concurrency.
	debugFlag int32
}

var (
	appConfig *AppConfig
	once      sync.Once
)

func GetAppConfig() *AppConfig {
	once.Do(func() {
		appConfig = &AppConfig{
			Debug:    getEnvBool("APP_DEBUG", false),
			LogLevel: strings.ToUpper(getEnvOrDefault("LOG_LEVEL", "ERROR")),
		}
		if appConfig.Debug {
			appConfig.debugFlag = 1
		}
		appConfig.initLogger()
		appConfig.RetentionDays = parsePositiveInt("CLICKHOUSE_RETENTION_DAYS", 30)
		appConfig.RetentionIntervalHours = parsePositiveInt("CLICKHOUSE_RETENTION_INTERVAL_HOURS", 24)
	})
	return appConfig
}

func (c *AppConfig) initLogger() {
	logsDir := "logs"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		log.Printf("Failed to create logs directory: %v", err)
		return
	}

	c.logPath = filepath.Join(logsDir, "app.log")
	file, err := os.OpenFile(c.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		return
	}

	info, err := file.Stat()
	if err == nil {
		c.logSize = info.Size()
	}

	c.logFile = file
	c.logger = log.New(file, "", log.LstdFlags|log.Lshortfile)
	log.SetOutput(file)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// rotate checks file size and rotates if needed. Must be called with mu held.
func (c *AppConfig) rotate() {
	if c.logFile == nil || c.logSize < maxLogSize {
		return
	}

	c.logFile.Close()

	// Shift existing backups: app.log.2 -> app.log.3, app.log.1 -> app.log.2, etc.
	for i := maxLogBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", c.logPath, i)
		dst := fmt.Sprintf("%s.%d", c.logPath, i+1)
		os.Remove(dst)
		os.Rename(src, dst)
	}

	// Current log -> .1
	os.Rename(c.logPath, c.logPath+".1")

	// Open fresh file
	file, err := os.OpenFile(c.logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return
	}

	c.logFile = file
	c.logSize = 0
	c.logger = log.New(file, "", log.LstdFlags|log.Lshortfile)
	log.SetOutput(file)
}

// writeLog is the single write path — handles rotation check.
func (c *AppConfig) writeLog(format string, v ...interface{}) {
	if c.logger == nil {
		return
	}
	msg := fmt.Sprintf(format, v...)
	c.logger.Print(msg)
	c.logSize += int64(len(msg)) + 40 // approximate prefix overhead
	c.rotate()
}

// LogStartup writes a startup/critical message that always appears regardless
// of LOG_LEVEL. Use only for service start, stop, and fatal init failures.
func (c *AppConfig) LogStartup(format string, v ...interface{}) {
	msg := fmt.Sprintf("[STARTUP] "+format, v...)
	fmt.Println(msg)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeLog("[STARTUP] "+format, v...)
}

func (c *AppConfig) IsDebug() bool {
	return atomic.LoadInt32(&c.debugFlag) == 1
}

func (c *AppConfig) ShouldLog(level string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	levels := map[string]int{
		"DEBUG": 0,
		"INFO":  1,
		"WARN":  2,
		"ERROR": 3,
	}

	configLevel := levels[c.LogLevel]
	msgLevel := levels[strings.ToUpper(level)]

	return msgLevel >= configLevel
}

func (c *AppConfig) LogDebug(format string, v ...interface{}) {
	if !c.IsDebug() {
		return
	}
	if c.ShouldLog("DEBUG") {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.writeLog("[DEBUG] "+format, v...)
	}
}

func (c *AppConfig) LogInfo(format string, v ...interface{}) {
	if c.ShouldLog("INFO") {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.writeLog("[INFO] "+format, v...)
	}
}

func (c *AppConfig) LogWarn(format string, v ...interface{}) {
	if c.ShouldLog("WARN") {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.writeLog("[WARN] "+format, v...)
	}
}

func (c *AppConfig) LogError(format string, v ...interface{}) {
	if c.ShouldLog("ERROR") {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.writeLog("[ERROR] "+format, v...)
	}
}

func (c *AppConfig) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logFile != nil {
		log.SetOutput(os.Stdout)
		return c.logFile.Close()
	}
	return nil
}

func getEnvBool(key string, defaultValue bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	return strings.ToLower(val) == "true"
}

func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func parsePositiveInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		if appConfig != nil {
			appConfig.LogWarn("[Config] invalid value for %s: %q, using default %d", key, val, defaultVal)
		}
		return defaultVal
	}
	return n
}
