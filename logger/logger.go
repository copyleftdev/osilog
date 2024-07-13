package logger

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

func ConfigureLogger(logLevels string) error {
	logrus.SetFormatter(&prefixed.TextFormatter{
		FullTimestamp:   true,
		ForceColors:     true,
		ForceFormatting: true,
	})

	logLevelMap := map[logrus.Level]bool{
		logrus.InfoLevel:  false,
		logrus.WarnLevel:  false,
		logrus.ErrorLevel: false,
	}

	levels := strings.Split(logLevels, ",")
	for _, level := range levels {
		switch strings.TrimSpace(level) {
		case "info":
			logLevelMap[logrus.InfoLevel] = true
		case "warn":
			logLevelMap[logrus.WarnLevel] = true
		case "error":
			logLevelMap[logrus.ErrorLevel] = true
		default:
			return fmt.Errorf("unknown log level: %s", level)
		}
	}

	for level, enabled := range logLevelMap {
		if enabled {
			logrus.SetLevel(level)
			break
		}
	}

	return nil
}
