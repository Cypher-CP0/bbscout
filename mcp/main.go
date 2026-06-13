package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"

	"github.com/Cypher-CP0/bbscout/mcp/tools"
)

func main() {
	loadConfig()

	s := server.NewMCPServer(
		"bbscout",
		"0.1.0",
		server.WithToolCapabilities(true),
	)

	// register all tools
	tools.RegisterRecon(s)
	tools.RegisterCrawl(s)
	tools.RegisterScan(s)
	tools.RegisterProbe(s)
	tools.RegisterTriage(s)

	log.Println("[bbscout-mcp] server starting on stdio")

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("[bbscout-mcp] server error: %v", err)
	}
}

func loadConfig() {
	// try config relative to binary first, then working directory
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		viper.AddConfigPath(exeDir + "/config")
		viper.AddConfigPath(exeDir)
	}
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("[warn] could not load config: %v, using defaults", err)
	} else {
		log.Printf("[bbscout-mcp] loaded config: %s", viper.ConfigFileUsed())
	}

	// defaults
	viper.SetDefault("output_dir", "./output")
	viper.SetDefault("tools.subfinder", "subfinder")
	viper.SetDefault("tools.assetfinder", "assetfinder")
	viper.SetDefault("tools.dnsx", "dnsx")
	viper.SetDefault("tools.naabu", "naabu")
	viper.SetDefault("tools.httpx", "httpx")
	viper.SetDefault("tools.gowitness", "gowitness")
	viper.SetDefault("tools.katana", "katana")
	viper.SetDefault("tools.gau", "gau")
	viper.SetDefault("tools.waybackurls", "waybackurls")
	viper.SetDefault("tools.nuclei", "/home/prabhat/go/bin/nuclei")
	viper.SetDefault("tools.subzy", "subzy")
	viper.SetDefault("nuclei.templates", "~/.local/nuclei-templates")
	viper.SetDefault("nuclei.severity", "medium,high,critical")
	viper.SetDefault("ollama.host", "http://localhost:11434")
	viper.SetDefault("ollama.model", "qwen3:latest")
}