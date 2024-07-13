package cmd

import (
	"github.com/copyleftdev/osilog/capture"
	"github.com/copyleftdev/osilog/logger"
	"github.com/spf13/cobra"
)

var (
	interfaceName string
	logLevels     string
	rootCmd       = &cobra.Command{
		Use:   "osilog",
		Short: "Network monitoring tool",
		Long:  `Network monitoring tool to capture and analyze network packets.`,
		Run:   run,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&interfaceName, "interface", "i", "", "Network interface to capture packets from")
	rootCmd.PersistentFlags().StringVarP(&logLevels, "loglevels", "l", "info", "Log levels (info,warn,error)")
	rootCmd.MarkPersistentFlagRequired("interface")
}

func Execute() error {
	return rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) {
	logger.ConfigureLogger(logLevels)
	capture.CapturePackets(interfaceName)
}
