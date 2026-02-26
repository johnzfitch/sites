package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/BurntSushi/toml"
)

// --- Config types ---

type GlobalConfig struct {
	Root        string `toml:"root"`
	Caddyfile   string `toml:"caddyfile"`
	Log         string `toml:"log"`
	WebhookPort int    `toml:"webhook_port"` // port for webhook server (default: 9111)
}

type SiteConfig struct {
	Domain        string `toml:"domain"`
	Repo          string `toml:"repo"`
	Branch        string `toml:"branch"`
	Path          string `toml:"path"`           // optional subdirectory to serve
	DeployKey     string `toml:"deploy_key"`     // dota secret name for SSH deploy key
	WebhookSecret string `toml:"webhook_secret"` // dota secret name for GitHub webhook HMAC
	NoCaddy       bool   `toml:"no_caddy"`       // skip Caddyfile entry; serving managed externally
}

type Config struct {
	Global GlobalConfig            `toml:"global"`
	Sites  map[string]*SiteConfig  `toml:"sites"`
}

// --- Log entry ---

type LogEntry struct {
	Timestamp string `json:"ts"`
	Domain    string `json:"domain"`
	Action    string `json:"action"`
	Commit    string `json:"commit"`
	Prev      string `json:"prev,omitempty"`
	DurMs     int64  `json:"dur_ms"`
	Error     string `json:"error,omitempty"`
}

// --- Paths ---

var configPath = "/etc/sites/sites.toml"

// domainRe validates domain names: labels separated by dots, no path traversal.
var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)

// branchRe validates git branch names to prevent injection
var branchRe = regexp.MustCompile(`^[a-zA-Z0-9/_.-]+$`)

func init() {
	if p := os.Getenv("SITES_CONFIG"); p != "" {
		configPath = p
	}
}

// safeShort returns s[:n] with bounds safety.
func safeShort(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// --- Config I/O ---

func loadConfig() (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if cfg.Global.Root == "" {
		cfg.Global.Root = "/var/lib/sites"
	}
	if cfg.Global.Caddyfile == "" {
		cfg.Global.Caddyfile = "/etc/caddy/sites.conf"
	}
	if cfg.Global.Log == "" {
		cfg.Global.Log = filepath.Join(cfg.Global.Root, "deploy.log")
	}
	for name, site := range cfg.Sites {
		if site.Branch == "" {
			site.Branch = "main"
		}
		if site.Domain == "" {
			site.Domain = name
		}
	}
	return &cfg, nil
}

func saveConfig(cfg *Config) error {
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp := configPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := toml.NewEncoder(f)
	if err := enc.Encode(cfg); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, configPath)
}

// --- Dota integration ---
// dota is a post-quantum secrets manager (ML-KEM-768 + X25519).
// Deploy keys are stored encrypted in dota, extracted to tmpfs for git ops,
// and destroyed immediately after. Keys never touch persistent storage.

// tmpfsKeyDir returns a tmpfs-backed directory for ephemeral key storage.
// Linux: /dev/shm (always tmpfs). macOS/other: os.TempDir() (less ideal but works).
func tmpfsKeyDir() string {
	if runtime.GOOS == "linux" {
		if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
			return "/dev/shm/sites-keys"
		}
	}
	return filepath.Join(os.TempDir(), "sites-keys")
}

// getSecret retrieves a secret by name. Supports:
//   - "file:/path/to/secret" - read from file (for NixOS agenix secrets)
//   - "env:VAR_NAME" - read from environment variable
//   - "secretname" - read from dota vault
func getSecret(secretRef string) (string, error) {
	if strings.HasPrefix(secretRef, "file:") {
		path := strings.TrimPrefix(secretRef, "file:")
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read secret file %s: %w", path, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	if strings.HasPrefix(secretRef, "env:") {
		varName := strings.TrimPrefix(secretRef, "env:")
		val := os.Getenv(varName)
		if val == "" {
			return "", fmt.Errorf("env var %s not set", varName)
		}
		return val, nil
	}
	return dotaGet(secretRef)
}

func dotaGet(secretName string) (string, error) {
	cmd := exec.Command("dota", "get", secretName)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("dota get %s: %s", secretName, string(exitErr.Stderr))
		}
		return "", fmt.Errorf("dota get %s: %w", secretName, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// sshCommandForKey returns a GIT_SSH_COMMAND value that uses the given key file.
// StrictHostKeyChecking=accept-new: accept GitHub's host key on first use,
// reject if it changes (TOFU model — safer than =no which ignores changes).
func sshCommandForKey(keyPath string) string {
	knownHosts := filepath.Join(tmpfsKeyDir(), "known-hosts")
	return fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s -o IdentitiesOnly=yes", keyPath, knownHosts)
}

// withDeployKey extracts a deploy key from dota to tmpfs, runs fn with the
// GIT_SSH_COMMAND set, then destroys the key. If deployKey is empty, fn runs
// without SSH config (public repo mode).
func withDeployKey(deployKey string, fn func(env []string) error) error {
	if deployKey == "" {
		return fn(nil)
	}

	// Get key from dota
	key, err := dotaGet(deployKey)
	if err != nil {
		return fmt.Errorf("deploy key: %w", err)
	}

	// Write to tmpfs with random filename to avoid collisions
	kd := tmpfsKeyDir()
	if err := os.MkdirAll(kd, 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	var rndBytes [8]byte
	rand.Read(rndBytes[:])
	keyPath := filepath.Join(kd, hex.EncodeToString(rndBytes[:]))
	if err := os.WriteFile(keyPath, []byte(key+"\n"), 0600); err != nil {
		return fmt.Errorf("write deploy key: %w", err)
	}
	// Ensure cleanup even on panic
	defer func() {
		os.Remove(keyPath)
	}()

	sshCmd := sshCommandForKey(keyPath)
	env := append(os.Environ(), "GIT_SSH_COMMAND="+sshCmd)

	return fn(env)
}

// repoToSSH converts HTTPS GitHub URLs to SSH format for deploy key auth.
// https://github.com/user/repo → git@github.com:user/repo.git
func repoToSSH(repo string) string {
	repo = strings.TrimSuffix(repo, ".git")
	if strings.HasPrefix(repo, "https://github.com/") {
		path := strings.TrimPrefix(repo, "https://github.com/")
		return "git@github.com:" + path + ".git"
	}
	if strings.HasPrefix(repo, "http://github.com/") {
		path := strings.TrimPrefix(repo, "http://github.com/")
		return "git@github.com:" + path + ".git"
	}
	return repo
}

// effectiveRepo returns the repo URL to use for git operations.
// If a deploy key is configured, converts to SSH URL.
func effectiveRepo(site *SiteConfig) string {
	if site.DeployKey != "" {
		return repoToSSH(site.Repo)
	}
	return site.Repo
}

// --- Auto-detection helpers ---

// extractOwnerRepo normalizes a GitHub repo URL to "owner/repo" format.
func extractOwnerRepo(repo string) string {
	repo = strings.TrimPrefix(repo, "https://github.com/")
	repo = strings.TrimPrefix(repo, "http://github.com/")
	repo = strings.TrimPrefix(repo, "git@github.com:")
	repo = strings.TrimSuffix(repo, ".git")
	return repo
}

// checkRepoVisibility uses gh CLI to detect if repo is public or private.
// Returns "public", "private", or "unknown" if gh is not available or fails.
func checkRepoVisibility(repo string) string {
	ownerRepo := extractOwnerRepo(repo)
	cmd := exec.Command("gh", "api", fmt.Sprintf("repos/%s", ownerRepo), "--jq", ".visibility")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	visibility := strings.TrimSpace(string(out))
	if visibility == "private" {
		return "private"
	}
	return "public"
}

// canAutoSetup checks if gh CLI and dota are available for auto-setup.
func canAutoSetup() (ghOK, dotaOK bool) {
	// Check gh CLI: accept GH_TOKEN/GITHUB_TOKEN env vars or stored auth
	if os.Getenv("GH_TOKEN") != "" || os.Getenv("GITHUB_TOKEN") != "" {
		// Token in env - verify it actually works with a lightweight API call
		cmd := exec.Command("gh", "api", "user", "--jq", ".login")
		if _, err := cmd.Output(); err == nil {
			ghOK = true
		}
	} else {
		// Fall back to stored credentials check
		if out, err := exec.Command("gh", "auth", "status").CombinedOutput(); err == nil {
			ghOK = strings.Contains(string(out), "Logged in")
		}
	}

	// Check dota available
	if _, err := exec.Command("dota", "list").CombinedOutput(); err == nil {
		dotaOK = true
	}

	return ghOK, dotaOK
}

// generateDeployKey creates an ed25519 key, stores in dota, returns public key.
// If key already exists, returns empty pubKey and the existing secret name.
func generateDeployKey(domain string) (pubKey string, secretName string, err error) {
	secretName = "deploy-key/" + strings.ReplaceAll(domain, ".", "-")

	// Check if already exists
	if _, err := dotaGet(secretName); err == nil {
		// Key exists - retrieve it and extract public key
		return "", secretName, nil
	}

	// Generate to tmpfs
	kd := tmpfsKeyDir()
	if err := os.MkdirAll(kd, 0700); err != nil {
		return "", "", fmt.Errorf("mkdir: %w", err)
	}
	var rndBytes [8]byte
	rand.Read(rndBytes[:])
	keyPath := filepath.Join(kd, hex.EncodeToString(rndBytes[:]))
	defer os.Remove(keyPath)
	defer os.Remove(keyPath + ".pub")

	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath,
		"-N", "", "-C", "sites-"+domain)
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("ssh-keygen: %w", err)
	}

	privKey, err := os.ReadFile(keyPath)
	if err != nil {
		return "", "", fmt.Errorf("read key: %w", err)
	}
	pubKeyBytes, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return "", "", fmt.Errorf("read pubkey: %w", err)
	}

	// Store in dota (pass value as positional arg; dota reads from /dev/tty otherwise)
	cmd = exec.Command("dota", "set", secretName, string(privKey))
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("dota set: %w: %s", err, string(out))
	}

	return strings.TrimSpace(string(pubKeyBytes)), secretName, nil
}

// addGitHubDeployKey registers a public key with a GitHub repo.
func addGitHubDeployKey(ownerRepo, pubKey, title string) error {
	cmd := exec.Command("gh", "api",
		fmt.Sprintf("repos/%s/keys", ownerRepo),
		"--method", "POST",
		"-f", fmt.Sprintf("title=%s", title),
		"-f", fmt.Sprintf("key=%s", pubKey),
		"-F", "read_only=true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

// generateWebhookSecret creates a random secret, stores in dota.
// If secret already exists, returns the existing value.
func generateWebhookSecret(domain string) (secret string, secretName string, err error) {
	secretName = "webhook/" + strings.ReplaceAll(domain, ".", "-")

	// Check if already exists
	if existing, err := dotaGet(secretName); err == nil {
		return existing, secretName, nil
	}

	// Generate 32 bytes of randomness
	var buf [32]byte
	rand.Read(buf[:])
	secret = hex.EncodeToString(buf[:])

	// Store in dota (pass value as positional arg; dota reads from /dev/tty otherwise)
	cmd := exec.Command("dota", "set", secretName, secret)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("dota set: %w: %s", err, string(out))
	}

	return secret, secretName, nil
}

// createGitHubWebhook registers a webhook with a GitHub repo.
func createGitHubWebhook(ownerRepo, webhookURL, secret string) error {
	cmd := exec.Command("gh", "api",
		fmt.Sprintf("repos/%s/hooks", ownerRepo),
		"--method", "POST",
		"-f", "name=web",
		"-F", "active=true",
		"-f", fmt.Sprintf("config[url]=%s", webhookURL),
		"-f", "config[content_type]=json",
		"-f", fmt.Sprintf("config[secret]=%s", secret),
		"-f", "config[insecure_ssl]=0",
		"-f", "events[]=push")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

// --- Git operations ---

func gitClone(repo, branch, dest string) error {
	return gitCloneWithEnv(repo, branch, dest, nil)
}

func gitCloneWithEnv(repo, branch, dest string, env []string) error {
	cmd := exec.Command("git", "clone", "--depth", "1", "--branch", branch, "--single-branch", repo, dest)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if env != nil {
		cmd.Env = env
	}
	return cmd.Run()
}

func gitPull(dir, branch string) error {
	return gitPullWithEnv(dir, branch, nil)
}

func gitPullWithEnv(dir, branch string, env []string) error {
	cmd := exec.Command("git", "-C", dir, "fetch", "--depth", "1", "origin", branch)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if env != nil {
		cmd.Env = env
	}
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("git", "-C", dir, "reset", "--hard", "FETCH_HEAD")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func gitHead(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func gitHeadFull(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func gitHeadTime(dir string) time.Time {
	out, err := exec.Command("git", "-C", dir, "log", "-1", "--format=%ct").Output()
	if err != nil {
		return time.Time{}
	}
	var ts int64
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &ts)
	return time.Unix(ts, 0)
}

// --- Deploy logging ---

func appendLog(cfg *Config, entry LogEntry) {
	if err := os.MkdirAll(filepath.Dir(cfg.Global.Log), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "warn: log dir: %v\n", err)
		return
	}
	f, err := os.OpenFile(cfg.Global.Log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: log open: %v\n", err)
		return
	}
	defer f.Close()
	json.NewEncoder(f).Encode(entry)
}

// --- Caddyfile generation ---

// hasCaddyManagedSites returns true if any site in cfg generates a Caddyfile entry.
// When all sites have no_caddy = true, Caddyfile regeneration and caddy reload are skipped.
func hasCaddyManagedSites(cfg *Config) bool {
	for _, site := range cfg.Sites {
		if !site.NoCaddy {
			return true
		}
	}
	return false
}

func generateCaddyfile(cfg *Config) string {
	var b strings.Builder
	// Note: timestamp is written on actual file write, not here,
	// so content-based diffing works correctly.
	b.WriteString("# AUTO-GENERATED BY sites — DO NOT EDIT\n")

	// Sort sites by domain for stable output
	names := make([]string, 0, len(cfg.Sites))
	for name := range cfg.Sites {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		site := cfg.Sites[name]
		if site.NoCaddy {
			continue // serving managed externally (e.g. NixOS Caddy module)
		}
		rootDir := filepath.Join(cfg.Global.Root, name)
		if site.Path != "" {
			rootDir = filepath.Join(rootDir, site.Path)
		}
		commit := gitHead(filepath.Join(cfg.Global.Root, name))

		b.WriteString(fmt.Sprintf("%s {\n", site.Domain))
		b.WriteString(fmt.Sprintf("\troot * %s\n", rootDir))
		b.WriteString("\tfile_server\n")
		b.WriteString("\theader {\n")
		b.WriteString(fmt.Sprintf("\t\tX-Deployed-Commit \"%s\"\n", commit))
		b.WriteString("\t\t-Server\n")
		b.WriteString("\t}\n")
		b.WriteString("}\n\n")
	}

	return b.String()
}

// --- Reconciler ---

func reconcile(cfg *Config) {
	changed := false

	for name, site := range cfg.Sites {
		repoDir := filepath.Join(cfg.Global.Root, name)
		start := time.Now()
		repo := effectiveRepo(site)

		if site.DeployKey != "" {
			fmt.Fprintf(os.Stderr, "  [dota] using deploy key: %s\n", site.DeployKey)
		}

		if _, err := os.Stat(filepath.Join(repoDir, ".git")); os.IsNotExist(err) {
			// Clone
			fmt.Fprintf(os.Stderr, "  clone %s → %s\n", site.Domain, repo)
			if err := os.MkdirAll(filepath.Dir(repoDir), 0755); err != nil {
				fmt.Fprintf(os.Stderr, "  error: mkdir: %v\n", err)
				appendLog(cfg, LogEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Domain:    site.Domain,
					Action:    "error",
					Error:     err.Error(),
					DurMs:     time.Since(start).Milliseconds(),
				})
				continue
			}
			err := withDeployKey(site.DeployKey, func(env []string) error {
				return gitCloneWithEnv(repo, site.Branch, repoDir, env)
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "  error: clone: %v\n", err)
				appendLog(cfg, LogEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Domain:    site.Domain,
					Action:    "error",
					Error:     fmt.Sprintf("clone: %v", err),
					DurMs:     time.Since(start).Milliseconds(),
				})
				continue
			}
			commit := gitHead(repoDir)
			fmt.Fprintf(os.Stderr, "  cloned %s @ %s\n", site.Domain, commit)
			appendLog(cfg, LogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Domain:    site.Domain,
				Action:    "cloned",
				Commit:    commit,
				DurMs:     time.Since(start).Milliseconds(),
			})
			changed = true
		} else {
			// Pull
			before := gitHeadFull(repoDir)
			err := withDeployKey(site.DeployKey, func(env []string) error {
				return gitPullWithEnv(repoDir, site.Branch, env)
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "  error: pull %s: %v\n", site.Domain, err)
				appendLog(cfg, LogEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Domain:    site.Domain,
					Action:    "error",
					Commit:    gitHead(repoDir),
					Error:     fmt.Sprintf("pull: %v", err),
					DurMs:     time.Since(start).Milliseconds(),
				})
				continue
			}
			after := gitHeadFull(repoDir)
			if before != after {
				fmt.Fprintf(os.Stderr, "  updated %s: %s → %s\n", site.Domain, safeShort(before, 7), safeShort(after, 7))
				appendLog(cfg, LogEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Domain:    site.Domain,
					Action:    "updated",
					Commit:    safeShort(after, 7),
					Prev:      safeShort(before, 7),
					DurMs:     time.Since(start).Milliseconds(),
				})
				changed = true
			} else {
				fmt.Fprintf(os.Stderr, "  up-to-date %s @ %s\n", site.Domain, safeShort(after, 7))
			}
		}
	}

	// Remove directories for sites no longer in config
	entries, err := os.ReadDir(cfg.Global.Root)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if _, ok := cfg.Sites[name]; !ok {
				// Check it's actually a git repo before removing
				gitDir := filepath.Join(cfg.Global.Root, name, ".git")
				if _, err := os.Stat(gitDir); err == nil {
					fmt.Fprintf(os.Stderr, "  removing orphan: %s\n", name)
					os.RemoveAll(filepath.Join(cfg.Global.Root, name))
					appendLog(cfg, LogEntry{
						Timestamp: time.Now().UTC().Format(time.RFC3339),
						Domain:    name,
						Action:    "removed",
					})
					changed = true
				}
			}
		}
	}

	// Regenerate Caddyfile if anything changed and there are caddy-managed sites
	if changed && hasCaddyManagedSites(cfg) {
		newCaddy := generateCaddyfile(cfg)
		oldCaddy, _ := os.ReadFile(cfg.Global.Caddyfile)
		if newCaddy != string(oldCaddy) {
			fmt.Fprintf(os.Stderr, "  caddyfile changed, writing + reloading\n")
			if err := atomicWrite(cfg.Global.Caddyfile, newCaddy); err != nil {
				fmt.Fprintf(os.Stderr, "  error: write caddyfile: %v\n", err)
				return
			}
			caddyReload()
		}
	} else if !changed {
		fmt.Fprintf(os.Stderr, "  nothing changed\n")
	}
}

func atomicWrite(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	// Write temp file in same directory as target to guarantee same filesystem
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	// Fsync to ensure data is on disk before rename
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

func caddyReload() {
	// Try systemctl first (NixOS manages Caddy via systemd)
	cmd := exec.Command("systemctl", "reload", "caddy")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Fallback: try caddy CLI (auto-detect config location)
		cmd2 := exec.Command("caddy", "reload", "--config", "/etc/caddy/Caddyfile")
		cmd2.Stdout = os.Stderr
		cmd2.Stderr = os.Stderr
		if err2 := cmd2.Run(); err2 != nil {
			fmt.Fprintf(os.Stderr, "  warn: caddy reload failed (systemctl: %v, caddy cli: %v)\n", err, err2)
		}
	}
}

// --- CLI commands ---

func cmdAdd(args []string) {
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: sites add <domain> <repo> [--branch <branch>] [--path <subdir>] [--deploy-key <dota-secret>] [--no-caddy]\n")
		os.Exit(1)
	}
	domain := args[0]
	repo := args[1]

	// Validate domain to prevent path traversal and Caddyfile injection
	if !domainRe.MatchString(domain) {
		fmt.Fprintf(os.Stderr, "error: invalid domain %q (must be a valid hostname)\n", domain)
		os.Exit(1)
	}
	if len(domain) > 253 {
		fmt.Fprintf(os.Stderr, "error: domain too long (max 253 chars)\n")
		os.Exit(1)
	}

	// Normalize repo URL
	if !strings.Contains(repo, "://") && !strings.HasPrefix(repo, "git@") {
		repo = "https://github.com/" + repo
	}

	branch := "main"
	path := ""
	deployKey := ""
	noCaddy := false
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--branch":
			if i+1 < len(args) {
				branch = args[i+1]
				i++
			}
		case "--path":
			if i+1 < len(args) {
				path = args[i+1]
				i++
			}
		case "--deploy-key":
			if i+1 < len(args) {
				deployKey = args[i+1]
				i++
			}
		case "--private":
			// Convenience: auto-generate dota key name from domain
			deployKey = "deploy-key/" + strings.ReplaceAll(domain, ".", "-")
		case "--no-caddy":
			// Don't generate a Caddyfile entry; serving is managed externally
			noCaddy = true
		}
	}

	// Security: validate path to prevent traversal attacks
	if path != "" {
		clean := filepath.Clean(path)
		if strings.Contains(clean, "..") || filepath.IsAbs(clean) {
			fmt.Fprintf(os.Stderr, "error: path cannot contain .. or be absolute\n")
			os.Exit(1)
		}
		path = clean
	}

	// Security: validate branch name
	if !branchRe.MatchString(branch) {
		fmt.Fprintf(os.Stderr, "error: invalid branch name %q\n", branch)
		os.Exit(1)
	}

	// Derive a safe name from domain
	name := strings.ReplaceAll(domain, ".", "-")

	cfg, err := loadConfig()
	if err != nil {
		// Only create new config if the file doesn't exist.
		// If it exists but is malformed, report the error.
		if _, statErr := os.Stat(configPath); statErr == nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		cfg = &Config{
			Global: GlobalConfig{
				Root:      "/var/lib/sites",
				Caddyfile: "/etc/caddy/sites.conf",
			},
			Sites: make(map[string]*SiteConfig),
		}
	}
	if cfg.Sites == nil {
		cfg.Sites = make(map[string]*SiteConfig)
	}

	// --- Auto-detection flow ---
	ownerRepo := extractOwnerRepo(repo)
	webhookSecret := ""

	// Check if auto-setup is possible
	ghOK, dotaOK := canAutoSetup()

	if ghOK && dotaOK && deployKey == "" {
		// Auto-detect repo visibility
		visibility := checkRepoVisibility(repo)
		fmt.Fprintf(os.Stderr, "  repo: %s (%s)\n", ownerRepo, visibility)

		if visibility == "private" {
			// Generate and register deploy key
			fmt.Fprintf(os.Stderr, "  generating deploy key...\n")
			pubKey, keyName, err := generateDeployKey(domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  warn: could not generate deploy key: %v\n", err)
			} else {
				deployKey = keyName
				if pubKey != "" {
					// New key generated, register with GitHub
					fmt.Fprintf(os.Stderr, "  registering deploy key with GitHub...\n")
					if err := addGitHubDeployKey(ownerRepo, pubKey, "sites-"+domain); err != nil {
						fmt.Fprintf(os.Stderr, "  warn: could not add deploy key: %v\n", err)
						fmt.Fprintf(os.Stderr, "  add manually: %s\n", pubKey)
					} else {
						fmt.Fprintf(os.Stderr, "  deploy key registered\n")
					}
				}
			}
		}

		// Generate and register webhook (for both public and private)
		fmt.Fprintf(os.Stderr, "  setting up webhook...\n")
		webhookURL := fmt.Sprintf("https://%s/.sites/webhook", domain)
		secret, secretName, err := generateWebhookSecret(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warn: webhook secret generation failed: %v\n", err)
		} else {
			webhookSecret = secretName
			if err := createGitHubWebhook(ownerRepo, webhookURL, secret); err != nil {
				// Check if it's a duplicate webhook error (422)
				if strings.Contains(err.Error(), "422") && strings.Contains(err.Error(), "Hook already exists") {
					fmt.Fprintf(os.Stderr, "  webhook already exists\n")
				} else {
					fmt.Fprintf(os.Stderr, "  warn: could not create GitHub webhook: %v\n", err)
					fmt.Fprintf(os.Stderr, "  configure manually: %s with secret from dota\n", webhookURL)
				}
			} else {
				fmt.Fprintf(os.Stderr, "  webhook registered\n")
			}
		}
	} else if !ghOK || !dotaOK {
		if !ghOK {
			fmt.Fprintf(os.Stderr, "  note: gh CLI not available, skipping auto-setup\n")
		}
		if !dotaOK {
			fmt.Fprintf(os.Stderr, "  note: dota not initialized, skipping auto-setup\n")
		}
	}

	cfg.Sites[name] = &SiteConfig{
		Domain:        domain,
		Repo:          repo,
		Branch:        branch,
		Path:          path,
		DeployKey:     deployKey,
		WebhookSecret: webhookSecret,
		NoCaddy:       noCaddy,
	}

	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: save config: %v\n", err)
		os.Exit(1)
	}

	msg := fmt.Sprintf("added %s -> %s (%s)", domain, ownerRepo, branch)
	if deployKey != "" {
		msg += fmt.Sprintf(" [key: %s]", deployKey)
	}
	if webhookSecret != "" {
		msg += " [webhook: auto]"
	}
	fmt.Println(msg)

	// If deploy key was specified manually but doesn't exist, warn
	if deployKey != "" {
		if _, err := dotaGet(deployKey); err != nil {
			fmt.Fprintf(os.Stderr, "\nwarn: deploy key %q not found in dota yet\n", deployKey)
			fmt.Fprintf(os.Stderr, "  generate with: sites init-key %s\n", domain)
		}
	}
}

func cmdRemove(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: sites remove <domain>\n")
		os.Exit(1)
	}
	domain := args[0]
	name := strings.ReplaceAll(domain, ".", "-")

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Try exact name match first, then search by domain
	if _, ok := cfg.Sites[name]; ok {
		delete(cfg.Sites, name)
	} else {
		found := false
		for k, v := range cfg.Sites {
			if v.Domain == domain {
				delete(cfg.Sites, k)
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "error: site %q not found\n", domain)
			os.Exit(1)
		}
	}

	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: save config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("removed %s (run 'sites sync' to clean up)\n", domain)
}

func cmdList() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	names := make([]string, 0, len(cfg.Sites))
	for name := range cfg.Sites {
		names = append(names, name)
	}
	sort.Strings(names)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "DOMAIN\tREPO\tCOMMIT\tAGE\tAUTH\n")

	for _, name := range names {
		site := cfg.Sites[name]
		repoDir := filepath.Join(cfg.Global.Root, name)
		commit := "-"
		age := "-"
		auth := "public"

		if _, err := os.Stat(filepath.Join(repoDir, ".git")); err == nil {
			commit = gitHead(repoDir)
			t := gitHeadTime(repoDir)
			if !t.IsZero() {
				age = timeAgo(t)
			}
		} else {
			commit = "(not cloned)"
		}

		if site.DeployKey != "" {
			auth = "dota:" + site.DeployKey
		}

		// Shorten repo for display
		repo := site.Repo
		repo = strings.TrimPrefix(repo, "https://github.com/")
		repo = strings.TrimPrefix(repo, "git@github.com:")
		repo = strings.TrimSuffix(repo, ".git")

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", site.Domain, repo, commit, age, auth)
	}
	w.Flush()
}

func cmdSync() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "reconciling %d sites...\n", len(cfg.Sites))
	reconcile(cfg)
}

func cmdDeploy(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: sites deploy <domain>\n")
		os.Exit(1)
	}
	domain := args[0]

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Find the site
	name := strings.ReplaceAll(domain, ".", "-")
	site, ok := cfg.Sites[name]
	if !ok {
		for k, v := range cfg.Sites {
			if v.Domain == domain {
				name = k
				site = v
				ok = true
				break
			}
		}
	}
	if !ok {
		fmt.Fprintf(os.Stderr, "error: site %q not found\n", domain)
		os.Exit(1)
	}

	repoDir := filepath.Join(cfg.Global.Root, name)
	repo := effectiveRepo(site)
	start := time.Now()

	if site.DeployKey != "" {
		fmt.Fprintf(os.Stderr, "[dota] using deploy key: %s\n", site.DeployKey)
	}

	if _, err := os.Stat(filepath.Join(repoDir, ".git")); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "cloning %s...\n", site.Domain)
		err := withDeployKey(site.DeployKey, func(env []string) error {
			return gitCloneWithEnv(repo, site.Branch, repoDir, env)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "pulling %s...\n", site.Domain)
		before := gitHead(repoDir)
		err := withDeployKey(site.DeployKey, func(env []string) error {
			return gitPullWithEnv(repoDir, site.Branch, env)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		after := gitHead(repoDir)
		if before == after {
			fmt.Fprintf(os.Stderr, "already up-to-date @ %s\n", after)
		} else {
			fmt.Fprintf(os.Stderr, "updated %s → %s\n", before, after)
		}
	}

	commit := gitHead(repoDir)
	appendLog(cfg, LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Domain:    site.Domain,
		Action:    "deployed",
		Commit:    commit,
		DurMs:     time.Since(start).Milliseconds(),
	})

	// Regenerate Caddyfile
	newCaddy := generateCaddyfile(cfg)
	oldCaddy, _ := os.ReadFile(cfg.Global.Caddyfile)
	if newCaddy != string(oldCaddy) {
		atomicWrite(cfg.Global.Caddyfile, newCaddy)
		caddyReload()
		fmt.Fprintf(os.Stderr, "caddyfile updated + caddy reloaded\n")
	}
}

func cmdLog(args []string) {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(cfg.Global.Log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no log yet\n")
		return
	}

	domain := ""
	if len(args) > 0 {
		domain = args[0]
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// Show last 50 entries
	start := 0
	if len(lines) > 50 {
		start = len(lines) - 50
	}

	for _, line := range lines[start:] {
		if domain != "" && !strings.Contains(line, domain) {
			continue
		}
		fmt.Println(line)
	}
}

func cmdCaddy() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(generateCaddyfile(cfg))
}

func cmdWatch() {
	fmt.Fprintf(os.Stderr, "sitesd: reconciling every 60s (ctrl-c to stop)\n")

	// Handle shutdown signals cleanly
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Run immediately on start
	doReconcile := func() {
		cfg, err := loadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v (retrying in 60s)\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[%s] reconciling %d sites\n",
				time.Now().Format("15:04:05"), len(cfg.Sites))
			reconcile(cfg)
		}
	}

	doReconcile()

	for {
		select {
		case <-ticker.C:
			doReconcile()
		case s := <-sig:
			fmt.Fprintf(os.Stderr, "\nsitesd: received %s, shutting down\n", s)
			return
		}
	}
}

// --- Helpers ---

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// --- Bootstrap commands ---

func cmdInit() {
	// Load or create default config
	cfg, err := loadConfig()
	if err != nil {
		cfg = &Config{
			Global: GlobalConfig{
				Root:      "/var/lib/sites",
				Caddyfile: "/etc/caddy/sites.conf",
			},
			Sites: make(map[string]*SiteConfig),
		}
	}

	// Create directories
	dirs := []string{
		cfg.Global.Root,
		filepath.Dir(cfg.Global.Caddyfile),
		filepath.Dir(configPath),
		tmpfsKeyDir(),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "warn: mkdir %s: %v\n", d, err)
		} else {
			fmt.Printf("  ✓ %s\n", d)
		}
	}

	// Save config if it doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := saveConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "error: save config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  ✓ %s (created)\n", configPath)
	} else {
		fmt.Printf("  ✓ %s (exists)\n", configPath)
	}

	// Check dota availability
	if _, err := exec.LookPath("dota"); err != nil {
		fmt.Fprintf(os.Stderr, "\nwarn: dota not found in PATH\n")
		fmt.Fprintf(os.Stderr, "  private repos require dota for deploy key management\n")
	} else {
		fmt.Printf("  ✓ dota available\n")
	}

	fmt.Printf("\nsites initialized. add sites with:\n")
	fmt.Printf("  sites add example.com user/repo\n")
}

func cmdInitKey(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: sites init-key <domain>\n")
		fmt.Fprintf(os.Stderr, "\ngenerates an ed25519 deploy key, stores in dota, prints public key\n")
		os.Exit(1)
	}
	domain := args[0]

	// Security: validate domain
	if !domainRe.MatchString(domain) {
		fmt.Fprintf(os.Stderr, "error: invalid domain %q\n", domain)
		os.Exit(1)
	}

	keyName := "deploy-key/" + strings.ReplaceAll(domain, ".", "-")

	// Check if key already exists in dota
	if _, err := dotaGet(keyName); err == nil {
		fmt.Fprintf(os.Stderr, "error: key %q already exists in dota\n", keyName)
		fmt.Fprintf(os.Stderr, "  to regenerate: dota rm %s && sites init-key %s\n", keyName, domain)
		os.Exit(1)
	}

	// Generate ed25519 key pair to tmpfs
	kd := tmpfsKeyDir()
	if err := os.MkdirAll(kd, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "error: mkdir: %v\n", err)
		os.Exit(1)
	}
	var rndBytes [8]byte
	rand.Read(rndBytes[:])
	keyPath := filepath.Join(kd, hex.EncodeToString(rndBytes[:]))
	defer os.Remove(keyPath)
	defer os.Remove(keyPath + ".pub")

	// Generate key with ssh-keygen
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "sites-deploy-"+domain)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: ssh-keygen: %v\n", err)
		os.Exit(1)
	}

	// Read private key
	privKey, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read key: %v\n", err)
		os.Exit(1)
	}

	// Read public key
	pubKey, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read pubkey: %v\n", err)
		os.Exit(1)
	}

	// Store private key in dota
	cmd = exec.Command("dota", "set", keyName, string(privKey))
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: dota set: %v\n", err)
		fmt.Fprintf(os.Stderr, "  make sure dota is initialized: dota init\n")
		os.Exit(1)
	}

	fmt.Printf("deploy key generated and stored in dota as: %s\n\n", keyName)
	fmt.Printf("add this public key to GitHub → repo → Settings → Deploy keys:\n\n")
	fmt.Printf("  %s\n", strings.TrimSpace(string(pubKey)))
	fmt.Printf("\nthen run:\n")
	fmt.Printf("  sites add %s user/repo --private\n", domain)
}

func cmdCheck() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ok := true
	for name, site := range cfg.Sites {
		if site.DeployKey == "" {
			fmt.Printf("  ✓ %s (public)\n", name)
			continue
		}
		if _, err := dotaGet(site.DeployKey); err != nil {
			fmt.Printf("  ✗ %s: missing dota key %q\n", name, site.DeployKey)
			ok = false
		} else {
			fmt.Printf("  ✓ %s (dota: %s)\n", name, site.DeployKey)
		}
	}

	if !ok {
		fmt.Fprintf(os.Stderr, "\nsome deploy keys are missing. generate with:\n")
		fmt.Fprintf(os.Stderr, "  sites init-key <domain>\n")
		os.Exit(1)
	}
	fmt.Printf("\nall deploy keys present\n")
}

// --- Webhook server ---

// Rate limiting: track last deploy time per site to prevent DoS
var (
	rateLimitMu   sync.Mutex
	lastDeployAt  = make(map[string]time.Time)
	rateLimitSecs = 10 // minimum seconds between deploys for same site
)

// Global concurrency limit: max 5 simultaneous deploys to prevent resource exhaustion
var deploySemaphore = make(chan struct{}, 5)

// Replay protection: track recent webhook delivery IDs to prevent replay attacks
var (
	recentDeliveries   sync.Map // delivery ID -> time.Time
	deliveryExpiration = 5 * time.Minute
)

func canDeploy(siteName string) bool {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()
	last, ok := lastDeployAt[siteName]
	if !ok || time.Since(last) > time.Duration(rateLimitSecs)*time.Second {
		lastDeployAt[siteName] = time.Now()
		return true
	}
	return false
}

// GitHubWebhookPayload represents the relevant fields from GitHub push webhook
type GitHubWebhookPayload struct {
	Ref        string `json:"ref"`        // e.g. "refs/heads/main"
	Repository struct {
		FullName string `json:"full_name"` // e.g. "johnzfitch/definitelynot.ai"
		CloneURL string `json:"clone_url"` // e.g. "https://github.com/..."
		SSHURL   string `json:"ssh_url"`   // e.g. "git@github.com:..."
	} `json:"repository"`
	After  string `json:"after"`  // commit SHA after push
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
}

// verifyGitHubSignature validates the X-Hub-Signature-256 header using HMAC-SHA256.
// Uses constant-time comparison to prevent timing attacks.
func verifyGitHubSignature(body []byte, signature, secret string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)

	return subtle.ConstantTimeCompare(sigBytes, expected) == 1
}

// findSiteByRepo finds a site config by matching the repository URL.
// Returns site name and config, or empty string and nil if not found.
func findSiteByRepo(cfg *Config, repoFullName string) (string, *SiteConfig) {
	// repoFullName is like "johnzfitch/definitelynot.ai"
	for name, site := range cfg.Sites {
		// Normalize site repo for comparison
		siteRepo := site.Repo
		siteRepo = strings.TrimPrefix(siteRepo, "https://github.com/")
		siteRepo = strings.TrimPrefix(siteRepo, "git@github.com:")
		siteRepo = strings.TrimSuffix(siteRepo, ".git")

		if siteRepo == repoFullName {
			return name, site
		}
	}
	return "", nil
}

// deploySite performs a deploy for a single site (used by webhook handler)
func deploySite(cfg *Config, name string, site *SiteConfig) error {
	repoDir := filepath.Join(cfg.Global.Root, name)
	repo := effectiveRepo(site)
	start := time.Now()

	var deployErr error
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); os.IsNotExist(err) {
		// Clone
		if err := os.MkdirAll(filepath.Dir(repoDir), 0755); err != nil {
			deployErr = err
		} else {
			deployErr = withDeployKey(site.DeployKey, func(env []string) error {
				return gitCloneWithEnv(repo, site.Branch, repoDir, env)
			})
		}
	} else {
		// Pull
		deployErr = withDeployKey(site.DeployKey, func(env []string) error {
			return gitPullWithEnv(repoDir, site.Branch, env)
		})
	}

	commit := gitHead(repoDir)
	action := "webhook-deploy"
	errStr := ""
	if deployErr != nil {
		action = "webhook-error"
		errStr = deployErr.Error()
	}

	appendLog(cfg, LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Domain:    site.Domain,
		Action:    action,
		Commit:    commit,
		DurMs:     time.Since(start).Milliseconds(),
		Error:     errStr,
	})

	return deployErr
}

func cmdWebhook(args []string) {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	port := cfg.Global.WebhookPort
	if port == 0 {
		port = 9111
	}

	// Parse optional port override
	for i := 0; i < len(args); i++ {
		if args[i] == "--port" && i+1 < len(args) {
			fmt.Sscanf(args[i+1], "%d", &port)
		}
	}

	// Load webhook secrets into memory at startup
	// Supports: dota secrets, file:/path, env:VAR_NAME
	// Map: site name → secret
	secrets := make(map[string]string)
	for name, site := range cfg.Sites {
		if site.WebhookSecret == "" {
			continue
		}
		secret, err := getSecret(site.WebhookSecret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: could not load webhook secret for %s: %v\n", name, err)
			continue
		}
		secrets[name] = secret
	}

	if len(secrets) == 0 {
		fmt.Fprintf(os.Stderr, "error: no sites have webhook_secret configured\n")
		fmt.Fprintf(os.Stderr, "  add webhook_secret to sites.toml and store secret in dota\n")
		os.Exit(1)
	}

	// Webhook handler
	http.HandleFunc("/.sites/webhook", func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Read body (limit to 1MB to prevent memory exhaustion)
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Parse payload to find which repo this is for
		var payload GitHubWebhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Find matching site
		siteName, site := findSiteByRepo(cfg, payload.Repository.FullName)
		if siteName == "" {
			// No matching site - could be misconfigured webhook
			fmt.Fprintf(os.Stderr, "[webhook] unknown repo: %s\n", payload.Repository.FullName)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Get secret for this site
		secret, ok := secrets[siteName]
		if !ok {
			fmt.Fprintf(os.Stderr, "[webhook] no secret configured for %s\n", siteName)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Verify HMAC signature
		signature := r.Header.Get("X-Hub-Signature-256")
		if !verifyGitHubSignature(body, signature, secret) {
			fmt.Fprintf(os.Stderr, "[webhook] invalid signature for %s\n", siteName)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Replay protection: check if we've seen this delivery ID
		deliveryID := r.Header.Get("X-GitHub-Delivery")
		if deliveryID != "" {
			if _, seen := recentDeliveries.LoadOrStore(deliveryID, time.Now()); seen {
				fmt.Fprintf(os.Stderr, "[webhook] %s: replay detected (delivery %s)\n", siteName, deliveryID)
				w.WriteHeader(http.StatusConflict)
				return
			}
		}

		// Check this is for the right branch
		expectedRef := "refs/heads/" + site.Branch
		if payload.Ref != expectedRef {
			fmt.Fprintf(os.Stderr, "[webhook] %s: ignoring push to %s (want %s)\n",
				siteName, payload.Ref, expectedRef)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ignored: wrong branch"))
			return
		}

		// Rate limit check
		if !canDeploy(siteName) {
			fmt.Fprintf(os.Stderr, "[webhook] %s: rate limited\n", siteName)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		// Global concurrency limit: try to acquire semaphore
		select {
		case deploySemaphore <- struct{}{}:
			// acquired
		default:
			fmt.Fprintf(os.Stderr, "[webhook] %s: too many concurrent deploys\n", siteName)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		// Trigger deploy in background
		fmt.Fprintf(os.Stderr, "[webhook] %s: deploying %s by %s\n",
			siteName, safeShort(payload.After, 7), payload.Sender.Login)

		go func() {
			defer func() { <-deploySemaphore }() // release semaphore when done
			if err := deploySite(cfg, siteName, site); err != nil {
				fmt.Fprintf(os.Stderr, "[webhook] %s: deploy error: %v\n", siteName, err)
			} else {
				fmt.Fprintf(os.Stderr, "[webhook] %s: deployed @ %s\n",
					siteName, gitHead(filepath.Join(cfg.Global.Root, siteName)))
			}
		}()

		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("deploying"))
	})

	// Health endpoint
	http.HandleFunc("/.sites/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Start delivery ID cleanup goroutine (prevents memory leak from replay tracking)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			recentDeliveries.Range(func(key, value any) bool {
				if ts, ok := value.(time.Time); ok && now.Sub(ts) > deliveryExpiration {
					recentDeliveries.Delete(key)
				}
				return true
			})
		}
	}()

	// Start server
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Fprintf(os.Stderr, "sitesd: webhook server listening on %s\n", addr)
	fmt.Fprintf(os.Stderr, "  configured sites: %d with webhooks\n", len(secrets))

	// Handle shutdown
	srv := &http.Server{Addr: addr}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		fmt.Fprintf(os.Stderr, "\nsitesd: shutting down webhook server\n")
		srv.Close()
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// --- Main ---

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, `sites — mutable topology layer for static sites

usage:
  sites init                    bootstrap directories and config
  sites init-key <domain>       generate deploy key, store in dota, print pub key
  sites check                   verify all deploy keys exist in dota

  sites add <domain> <repo> [--branch main] [--path subdir] [--deploy-key <dota-secret>] [--no-caddy]
  sites remove <domain>
  sites list
  sites sync
  sites deploy <domain>
  sites log [domain]
  sites caddy

  sites watch                   poll mode: check every 60s (legacy)
  sites webhook [--port 9111]   webhook mode: HTTP server for GitHub webhooks (recommended)

auto-detection (when gh and dota are available):
  - Automatically detects public/private repos via GitHub API
  - Generates and registers deploy keys for private repos
  - Creates and registers webhooks for instant deploys
  - Stores all secrets in dota (post-quantum secure)

flags:
  --deploy-key <name>   override: use specific dota secret for SSH deploy key
  --no-caddy            skip Caddyfile entry; use when Caddy is managed externally (e.g. NixOS)

prerequisites for auto-setup:
  1. gh auth login --scopes repo,admin:public_key
  2. dota init  (as the caddy user on server)

config: %s (override with SITES_CONFIG env var)
`, configPath)
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "init":
		cmdInit()
	case "init-key":
		cmdInitKey(args)
	case "check":
		cmdCheck()
	case "add":
		cmdAdd(args)
	case "remove", "rm":
		cmdRemove(args)
	case "list", "ls":
		cmdList()
	case "sync":
		cmdSync()
	case "deploy":
		cmdDeploy(args)
	case "log", "logs":
		cmdLog(args)
	case "caddy":
		cmdCaddy()
	case "watch":
		cmdWatch()
	case "webhook":
		cmdWebhook(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(1)
	}
}
