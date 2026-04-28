package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vamsiv/aegisbox/pkg/image"
	"github.com/vamsiv/aegisbox/pkg/runtime"
)

func main() {
	root := &cobra.Command{
		Use:   "aegisbox",
		Short: "AegisBox — purpose-built container runtime for deploying LLMs safely",
		Long: `AegisBox enforces four safety pillars for contained LLM deployments:
  1. Resource isolation (cgroups v2 + Linux namespaces)
  2. Output filtering via a WASM-extensible classifier chain
  3. Reproducible deployments with BLAKE3-hashed ABX images
  4. Network/syscall restrictions`,
	}

	root.AddCommand(runCmd(), buildCmd(), inspectCmd(), psCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCmd() *cobra.Command {
	var cfgFile string
	cmd := &cobra.Command{
		Use:   "run <image>",
		Short: "Run an ABX image inside an isolated container",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			img, err := image.Load(args[0])
			if err != nil {
				return fmt.Errorf("loading image: %w", err)
			}
			c, err := runtime.NewContainer(img, cfgFile)
			if err != nil {
				return fmt.Errorf("creating container: %w", err)
			}
			return c.Run()
		},
	}
	cmd.Flags().StringVar(&cfgFile, "config", "config/aegisbox.yaml", "runtime config file")
	return cmd
}

func buildCmd() *cobra.Command {
	var tag string
	cmd := &cobra.Command{
		Use:   "build <dir>",
		Short: "Build an ABX image from a model directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			b := image.NewBuilder(args[0], tag)
			out, err := b.Build()
			if err != nil {
				return fmt.Errorf("build failed: %w", err)
			}
			fmt.Printf("Built image: %s\n", out)
			return nil
		},
	}
	cmd.Flags().StringVarP(&tag, "tag", "t", "", "image tag (modelId:version)")
	return cmd
}

func inspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <image>",
		Short: "Show image manifest, SBOM, and signatures",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			img, err := image.Load(args[0])
			if err != nil {
				return fmt.Errorf("loading image: %w", err)
			}
			img.Inspect(os.Stdout)
			return nil
		},
	}
}

func psCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ps",
		Short: "List running containers",
		RunE: func(_ *cobra.Command, _ []string) error {
			runtime.ListContainers(os.Stdout)
			return nil
		},
	}
}
