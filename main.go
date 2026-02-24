package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/BurntSushi/toml"
)

// --- Config types ---

type GlobalConfig struct {
	Root      string `toml:"root"`
	Caddyfile string `toml:"caddyfile"`
	Log       string `toml:"log"`
}

type SiteConfig struct {
	Domain    string `toml:"domain"`
	Repo      string `toml:"repo"`
	Branch    string `toml:"branch"`
	Path      string `toml:"path"`       // optional subdirectory to serve
	DeployKey string `toml:"deploy_key"` // dota secret name for SSH deploy key
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

	// Regenerate Caddyfile if anything changed
	if changed {
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
	} else {
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
		fmt.Fprintf(os.Stderr, "usage: sites add <domain> <repo> [--branch <branch>] [--path <subdir>] [--deploy-key <dota-secret>]\n")
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
		}
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

	cfg.Sites[name] = &SiteConfig{
		Domain:    domain,
		Repo:      repo,
		Branch:    branch,
		Path:      path,
		DeployKey: deployKey,
	}

	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: save config: %v\n", err)
		os.Exit(1)
	}

	msg := fmt.Sprintf("added %s → %s (%s)", domain, repo, branch)
	if deployKey != "" {
		msg += fmt.Sprintf(" [dota: %s]", deployKey)
	}
	fmt.Println(msg)

	if deployKey != "" {
		// Verify key exists in dota
		if _, err := dotaGet(deployKey); err != nil {
			fmt.Fprintf(os.Stderr, "\nwarn: deploy key %q not found in dota yet\n", deployKey)
			fmt.Fprintf(os.Stderr, "  store it with: dota set %s \"$(cat ~/.ssh/deploy_key)\"\n", deployKey)
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

// --- Main ---

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, `sites — mutable topology layer for static sites

usage:
  sites add <domain> <repo> [--branch main] [--path subdir] [--deploy-key <dota-secret>] [--private]
  sites remove <domain>
  sites list
  sites sync
  sites deploy <domain>
  sites log [domain]
  sites caddy
  sites watch

flags:
  --deploy-key <name>   dota secret name containing SSH deploy key
  --private             shorthand: auto-names dota key as deploy-key/<domain>

private repo setup:
  1. ssh-keygen -t ed25519 -f key -N ""
  2. add key.pub to GitHub repo → Settings → Deploy keys
  3. dota set deploy-key/my-site "$(cat key)"
  4. sites add my-site.com user/repo --private

config: %s (override with SITES_CONFIG env var)
`, configPath)
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
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
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(1)
	}
}
