package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var banner = `
██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
██████╔╝██████╔╝███████╗██║     ██║   ██║██║   ██║   ██║   
██╔══██╗██╔══██╗╚════██║██║     ██║   ██║██║   ██║   ██║   
██████╔╝██████╔╝███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   
        bug bounty recon & triage — v0.1.0
`

var rootCmd = &cobra.Command{
	Use:   "bbscout",
	Short: "Automated bug bounty recon & triage tool",
	Long:  `bbscout — modular recon pipeline for bug bounty hunting.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		fmt.Print(banner)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("$HOME/.bbscout")

	// sensible defaults so the tool works even without a config file
	viper.SetDefault("output_dir", "./output")
	viper.SetDefault("wordlist", "./wordlists/dns.txt")
	viper.SetDefault("tools.subfinder", "subfinder")
	viper.SetDefault("tools.assetfinder", "assetfinder")
	viper.SetDefault("tools.dnsx", "dnsx")
	viper.SetDefault("tools.naabu", "naabu")
	viper.SetDefault("tools.httpx", "httpx")
	viper.SetDefault("tools.gowitness", "gowitness")
	viper.SetDefault("tools.katana", "katana")
	viper.SetDefault("tools.gau", "gau")
	viper.SetDefault("tools.nuclei", "nuclei")
	viper.SetDefault("tools.subzy", "subzy")
	viper.SetDefault("ollama.host", "http://localhost:11434")
	viper.SetDefault("ollama.model", "qwen2.5-coder")
	viper.SetDefault("nuclei.severity", "medium,high,critical")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("[bbscout] no config file found, using defaults")
	} else {
		fmt.Println("[bbscout] loaded config:", viper.ConfigFileUsed())
	}
}