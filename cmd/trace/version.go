package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var Version = "0.1.0-dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Trace v%s\n", Version)
		},
	}
}
