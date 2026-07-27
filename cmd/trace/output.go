package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func out(cmd *cobra.Command) io.Writer {
	w := cmd.OutOrStdout()
	if w == nil {
		return io.Discard
	}
	return w
}

func outf(cmd *cobra.Command, format string, a ...any) {
	fmt.Fprintf(out(cmd), format, a...)
}

func outln(cmd *cobra.Command, a ...any) {
	fmt.Fprintln(out(cmd), a...)
}

func outstr(cmd *cobra.Command, a ...any) {
	fmt.Fprint(out(cmd), a...)
}
