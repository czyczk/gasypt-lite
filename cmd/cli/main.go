package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/czyczk/gasypt-lite"
)

var (
	algorithm  string
	iterations int
	wrapOutput bool
	quiet      bool
	input      string
	password   string
	inputFile  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "gasypt-lite",
		Short: "Password-based encryption tool",
		Long:  "gasypt-lite provides AES-256-CBC, SM4-GCM, and SM4-CBC password-based encryption.",
	}

	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Silence non-fatal warnings")

	encryptCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a plaintext value",
		Run:   runEncrypt,
	}
	encryptCmd.Flags().StringVarP(&algorithm, "algorithm", "a", "PBEWithHMACSHA512AndAES_256", "Encryption algorithm")
	encryptCmd.Flags().IntVar(&iterations, "iterations", 0, "Override PBKDF2 iteration count")
	encryptCmd.Flags().BoolVar(&wrapOutput, "wrap", false, "Wrap output in ENC(...) (AES only)")
	addInputFlags(encryptCmd)

	decryptCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt an encrypted value",
		Run:   runDecrypt,
	}
	decryptCmd.Flags().StringVarP(&algorithm, "algorithm", "a", "PBEWithHMACSHA512AndAES_256", "Encryption algorithm")
	decryptCmd.Flags().IntVar(&iterations, "iterations", 0, "Override PBKDF2 iteration count")
	addInputFlags(decryptCmd)

	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func addInputFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&input, "input", "i", "", "Input value (plaintext or encrypted)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Password for key derivation")
	cmd.Flags().StringVarP(&inputFile, "file", "f", "", "Read input from file instead of -i")
	cmd.MarkFlagRequired("password")
}

func readInput() string {
	if inputFile != "" {
		data, err := os.ReadFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %q: %v\n", inputFile, err)
			os.Exit(1)
		}
		return strings.TrimRight(string(data), "\r\n")
	}
	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: either --input or --file is required")
		os.Exit(1)
	}
	return input
}

func getAlgorithm() (gasypt.Algorithm, error) {
	algo, ok := gasypt.ParseAlgorithm(algorithm)
	if !ok {
		pflag.Usage()
		return 0, fmt.Errorf("invalid algorithm: %q (valid: %s)", algorithm,
			strings.Join(gasypt.ValidAlgorithmNames(), ", "))
	}
	return algo, nil
}

func getIterations(algo gasypt.Algorithm) int {
	if iterations > 0 {
		return iterations
	}
	return algo.DefaultIterations()
}

func runEncrypt(cmd *cobra.Command, args []string) {
	algo, err := getAlgorithm()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	plaintext := readInput()
	iters := getIterations(algo)

	if !quiet && len(password) < 8 {
		fmt.Fprintln(os.Stderr, "Warning: password is shorter than 8 characters")
	}

	var result string
	if iterations > 0 {
		result = gasypt.EncryptWithIterations(algo, password, plaintext, iters)
	} else {
		result = gasypt.EncryptWith(algo, password, plaintext)
	}

	if wrapOutput {
		if algo == gasypt.PBEWithHMACSHA512AndAES_256 {
			result = gasypt.WrapEnc(result)
		} else {
			if !quiet {
				fmt.Fprintln(os.Stderr, "Warning: --wrap only supported for AES-256-CBC")
			}
		}
	}

	fmt.Println(result)
}

func runDecrypt(cmd *cobra.Command, args []string) {
	if !quiet && len(password) < 8 {
		fmt.Fprintln(os.Stderr, "Warning: password is shorter than 8 characters")
	}

	encoded := readInput()
	if gasypt.IsEncValue(encoded) {
		algo, err := getAlgorithm()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		result, err := gasypt.DecryptEncWith(algo, encoded, password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(result)
		return
	}

	algo, err := getAlgorithm()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	iters := getIterations(algo)

	var result string
	if iterations > 0 {
		result, err = gasypt.DecryptWithIterations(algo, password, encoded, iters)
	} else {
		result, err = gasypt.DecryptWith(algo, password, encoded)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(result)
}
