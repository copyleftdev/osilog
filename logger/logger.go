package logger

import (
	"strings"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

func ConfigureLogger(logLevels string) {
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
			logrus.Fatalf("Unknown log level: %s", level)
		}
	}

	for level, enabled := range logLevelMap {
		if enabled {
			logrus.SetLevel(level)
			break
		}
	}
}
