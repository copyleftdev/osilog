package logger

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestConfigureLogger(t *testing.T) {
	err := ConfigureLogger("info")
	assert.NoError(t, err)

	expectedLevel := logrus.InfoLevel
	actualLevel := logrus.GetLevel()

	if actualLevel != expectedLevel {
		t.Fatalf("Expected log level to be %v, got %v", expectedLevel, actualLevel)
	}

	assert.Equal(t, expectedLevel, actualLevel)
}
