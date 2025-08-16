package main

import (
	"hosts-cli/cli"
	"hosts-cli/core"
	"hosts-cli/server"
	"os"
)

func main() {
	// Delegate all CLI handling to the Cobra runner.
	r := cli.Runner{
		Deps: cli.Deps{
			HostsPath:      core.HostsPath,
			BackupDir:      core.BackupDir,
			ReadHosts:      core.ReadHosts,
			WriteHosts:     core.WriteHosts,
			ValidateEntry:  core.ValidateEntry,
			CalculateStats: core.CalculateStats,
			CreateBackup:   core.CreateBackup,
			GetBackups:     core.GetBackups,
			RestoreBackup:  core.RestoreBackup,
			HostExists:     core.HostExists,
			StartWebServer: server.StartWebServerCobraBridge,
		},
	}

	code := r.Execute(os.Args[1:])
	os.Exit(code)
}
