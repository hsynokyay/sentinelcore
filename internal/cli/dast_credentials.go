package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"golang.org/x/term"

	"github.com/sentinelcore/sentinelcore/internal/dast/credentials"
)

// CredentialsEnvCustomerID is the env var operators must export to identify
// the SentinelCore tenant for `dast credentials` operations.
const CredentialsEnvCustomerID = "SENTINEL_CUSTOMER_ID"

// RunCredentialsCommand routes `sentinelcore-cli dast credentials <subcmd>`
// against a Store. The CLI binary constructs the Store (Postgres + KMS
// provider) at startup and passes it in.
func RunCredentialsCommand(args []string, store credentials.Store) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: dast credentials add|list|remove [--bundle <uuid>] [--key <name>]")
	}
	switch args[0] {
	case "add":
		return runCredAdd(args[1:], store, os.Stdin, os.Stderr)
	case "list":
		return runCredList(args[1:], store, os.Stdout)
	case "remove":
		return runCredRemove(args[1:], store)
	default:
		return fmt.Errorf("unknown credentials subcommand %q", args[0])
	}
}

// runCredAdd reads a credential value from the terminal (no echo) and saves
// it under (bundleID, vaultKey) for the operator's customer.
func runCredAdd(args []string, store credentials.Store, in io.Reader, errOut io.Writer) error {
	bundleID, vaultKey, err := parseBundleAndKey(args)
	if err != nil {
		return err
	}
	if vaultKey == "" {
		return fmt.Errorf("--key required for credentials add")
	}
	customerID, err := requireCustomerID()
	if err != nil {
		return err
	}

	pw, err := readSecretFromTerminal(in, errOut)
	if err != nil {
		return err
	}
	if len(pw) == 0 {
		return fmt.Errorf("empty value rejected")
	}

	if err := store.Save(context.Background(), customerID, bundleID, vaultKey, pw); err != nil {
		return fmt.Errorf("save: %w", err)
	}
	fmt.Fprintf(errOut, "Saved credential: bundle=%s key=%s\n", bundleID, vaultKey)
	return nil
}

// runCredList prints vault keys (one per line) for a bundle.
func runCredList(args []string, store credentials.Store, out io.Writer) error {
	bundleID, _, err := parseBundleAndKey(args)
	if err != nil {
		return err
	}
	keys, err := store.ListKeys(context.Background(), bundleID)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	for _, k := range keys {
		fmt.Fprintln(out, k)
	}
	return nil
}

// runCredRemove deletes a single (bundleID, vaultKey) row.
func runCredRemove(args []string, store credentials.Store) error {
	bundleID, vaultKey, err := parseBundleAndKey(args)
	if err != nil {
		return err
	}
	if vaultKey == "" {
		return fmt.Errorf("--key required for credentials remove")
	}
	if err := store.Delete(context.Background(), bundleID, vaultKey); err != nil {
		return fmt.Errorf("remove: %w", err)
	}
	return nil
}

// parseBundleAndKey scans args for --bundle <uuid> and --key <name>. Both
// are optional in this parser — callers enforce per-subcommand requirements.
// --bundle is always required and validated as a UUID.
func parseBundleAndKey(args []string) (uuid.UUID, string, error) {
	var bundle, key string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--bundle":
			if i+1 < len(args) {
				bundle = args[i+1]
				i++
			}
		case "--key":
			if i+1 < len(args) {
				key = args[i+1]
				i++
			}
		}
	}
	if bundle == "" {
		return uuid.Nil, "", fmt.Errorf("--bundle <uuid> required")
	}
	id, err := uuid.Parse(bundle)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("invalid bundle uuid %q: %w", bundle, err)
	}
	return id, key, nil
}

// requireCustomerID reads SENTINEL_CUSTOMER_ID from the environment.
func requireCustomerID() (uuid.UUID, error) {
	v := os.Getenv(CredentialsEnvCustomerID)
	if v == "" {
		return uuid.Nil, fmt.Errorf("%s environment variable not set", CredentialsEnvCustomerID)
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid %s: %w", CredentialsEnvCustomerID, err)
	}
	return id, nil
}

// readSecretFromTerminal prompts on errOut and reads a line of input from in
// without echoing. When in is *os.File pointing at a terminal we use
// term.ReadPassword; otherwise (redirected stdin in tests/CI) we fall back
// to a plain read so non-interactive flows still work.
func readSecretFromTerminal(in io.Reader, errOut io.Writer) ([]byte, error) {
	fmt.Fprint(errOut, "credential value (input hidden): ")
	defer fmt.Fprintln(errOut)

	if f, ok := in.(*os.File); ok {
		fd := int(f.Fd())
		if term.IsTerminal(fd) {
			pw, err := term.ReadPassword(fd)
			if err != nil {
				return nil, fmt.Errorf("read terminal: %w", err)
			}
			return pw, nil
		}
	}
	// Non-tty input (CI / pipes / tests): read a single line.
	buf := make([]byte, 0, 64)
	one := make([]byte, 1)
	for {
		n, err := in.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				break
			}
			if one[0] != '\r' {
				buf = append(buf, one[0])
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	return buf, nil
}
