# sites / sitesd — Architecture Diagrams

## 1. System Overview — The Layering Philosophy

```
┌─────────────────────────────────────────────────────────────┐
│                     IMMUTABLE LAYER                         │
│                        (NixOS)                              │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │  Caddy   │  │ systemd  │  │  agenix  │  │ firewall  │  │
│  │ (binary) │  │ (units)  │  │(secrets) │  │ (nftables)│  │
│  └────┬─────┘  └────┬─────┘  └──────────┘  └───────────┘  │
│       │              │                                      │
│       │   import     │   runs                               │
│       │   sites.conf │   sitesd                             │
└───────┼──────────────┼──────────────────────────────────────┘
        │              │
╔═══════╧══════════════╧══════════════════════════════════════╗
║                    MUTABLE LAYER                            ║
║                      (sites)                                ║
║                                                             ║
║  sites.toml ──→ reconciler ──→ /var/lib/sites/              ║
║  (desired)      (converge)     (actual repos)               ║
║                     │                                       ║
║                     ├──→ sites.conf                         ║
║                     │    (generated Caddyfile)              ║
║                     │                                       ║
║                     └──→ dota (deploy keys)                 ║
║                          tmpfs → git op → destroy           ║
╚═════════════════════════════════════════════════════════════╝
        │
        │  git clone / pull (SSH or HTTPS)
        ▼
┌─────────────────────────────────────────────────────────────┐
│                     SOURCE LAYER                            │
│                      (GitHub)                               │
│                                                             │
│  user/example.com                   (public)                │
│  user/blog                          (public)                │
│  user/staging                       (private → dota key)    │
│  ...                                                        │
└─────────────────────────────────────────────────────────────┘
```


## 2. Reconcile Loop — State Machine

```
                    ┌─────────────┐
                    │ Load        │
                    │ sites.toml  │
                    │ (desired)   │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Validate    │
                    │ domains     │
                    │ (regex)     │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Scan        │
                    │ /var/lib/   │
                    │ sites/      │
                    │ (actual)    │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌───────────┐ ┌────────┐ ┌──────────┐
        │ missing?  │ │ stale? │ │ orphan?  │
        │           │ │        │ │          │
        │ if deploy │ │ dota → │ │ rm -rf   │
        │ key:      │ │ tmpfs  │ │ (only if │
        │ dota →    │ │ pull   │ │ has .git)│
        │ tmpfs →   │ │ clean  │ │          │
        │ clone →   │ │ key    │ │          │
        │ clean key │ │        │ │          │
        └─────┬─────┘ └───┬────┘ └────┬─────┘
              │            │           │
              └────────────┼───────────┘
                           │
                           ▼
                    ┌─────────────┐     ┌──────────────┐
                    │  changed?   │─no─▶│   done       │
                    └──────┬──────┘     └──────────────┘
                           │ yes
                           ▼
                    ┌─────────────┐
                    │ generate    │
                    │ Caddyfile   │
                    │ (sorted by  │
                    │  domain)    │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐     ┌──────────────┐
                    │ diff with   │─no─▶│   done       │
                    │ existing?   │     └──────────────┘
                    └──────┬──────┘
                           │ yes
                           ▼
                    ┌─────────────┐
                    │ atomic      │
                    │ write:      │
                    │  tmp file   │
                    │  fsync      │
                    │  rename     │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ caddy       │
                    │ reload:     │
                    │  systemctl  │
                    │  (fallback: │
                    │   caddy cli)│
                    └─────────────┘
```


## 3. Data Flow — What Lives Where

```
  YOU (laptop)                    SERVER
 ─────────────                   ──────────────────────────────

  git push ──────────────────▶  GitHub
                                   │
                                   │  (polled every 60s)
                                   ▼
                              ┌──────────┐
                              │  sitesd  │ (systemd service)
                              │          │
                              │ reads:   │
                              │ sites.   │──────▶ /etc/sites/
                              │ toml     │        sites.toml
                              │          │
                              │ calls:   │
                              │ dota get │──────▶ dota vault
                              │          │        (ML-KEM-768 +
                              │          │         X25519)
                              │          │
                              │ tmpfs:   │
                              │ keys to  │──────▶ /dev/shm/sites-keys/
                              │ RAM only │        (random filename,
                              │          │         deleted after use)
                              │          │
                              │ writes:  │
                              │ repos    │──────▶ /var/lib/sites/
                              │          │        ├── example-com/
                              │          │        ├── blog-example-com/
                              │          │        └── staging-example-com/
                              │          │
                              │ emits:   │
                              │ caddy    │──────▶ /etc/caddy/
                              │ config   │        sites.conf
                              │          │
                              │ logs:    │
                              │ deploys  │──────▶ /var/lib/sites/
                              │          │        deploy.log (JSON lines)
                              └──────────┘
                                   │
                                   │ systemctl reload caddy
                                   ▼
                              ┌──────────┐
                              │  Caddy   │
                              │          │
                              │ imports  │◀───── /etc/caddy/sites.conf
                              │ serves   │◀───── /var/lib/sites/*/
                              │          │
                              └──────────┘
                                   │
                                   ▼
                              HTTPS traffic
                              example.com
                              blog.example.com
                              staging.example.com
```


## 4. CLI Commands — User Workflow

```
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  $ sites add blog.example.com user/blog                        │
│  added blog.example.com → github.com/user/blog                │
│                │                                               │
│  $ sites add staging.example.com user/staging --private        │
│  added staging.example.com → ... [dota: deploy-key/staging…]  │
│                │                                               │
│                ▼                                               │
│         ┌─────────────┐                                        │
│         │ sites.toml  │  (desired state updated)               │
│         │             │  (domain validated via regex)           │
│         └─────────────┘                                        │
│                                                                │
│  $ sites sync                                                  │
│  reconciling 3 sites...                                        │
│    clone blog.example.com → github.com/...                     │
│    [dota] using deploy key: deploy-key/staging-example-com     │
│    up-to-date staging.example.com @ 2d9f1a3                    │
│    up-to-date example.com @ a3f8c2d                            │
│    caddyfile changed, writing + reloading                      │
│                │                                               │
│                ▼                                               │
│  ┌──────────────────────────────────────────────┐              │
│  │ /var/lib/sites/blog-example-com/ (cloned)    │              │
│  │ /etc/caddy/sites.conf       (regenerated)    │              │
│  │ /var/lib/sites/deploy.log   (entry added)    │              │
│  │ caddy                       (reloaded)       │              │
│  └──────────────────────────────────────────────┘              │
│                                                                │
│  $ sites list                                                  │
│  DOMAIN                    REPO              COMMIT  AGE  AUTH │
│  blog.example.com          user/blog         7bc1e4f 10s  pub  │
│  example.com               user/example…     a3f8c2d 2m   pub  │
│  staging.example.com       user/staging      2d9f1a3 3d   dota │
│                                                                │
│  $ sites deploy staging.example.com                            │
│  [dota] using deploy key: deploy-key/staging-example-com       │
│  pulling staging.example.com...                                │
│  updated 2d9f1a3 → e4c7b21                                    │
│  caddyfile updated + caddy reloaded                            │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```


## 5. Daemon Mode — sitesd Lifecycle

```
        boot
          │
          ▼
    ┌───────────┐
    │  systemd  │
    │  starts   │
    │  sitesd   │
    └─────┬─────┘
          │
          ▼
    ┌───────────┐     ┌─────────────────────────────┐
    │ reconcile │────▶│ clone/pull/remove as needed  │
    │ (initial) │     │ dota keys extracted to tmpfs │
    └─────┬─────┘     │ then destroyed after git ops │
          │           └─────────────────────────────┘
          ▼
    ┌───────────┐
    │  select   │◀─── event loop (not blocking sleep)
    │  {        │
    │  ticker.C │──▶ reconcile
    │  sig      │──▶ clean shutdown
    │  }        │
    └─────┬─────┘
          │
          │  every 60s
          ▼
    ┌───────────┐     ┌─────────────────────────────┐
    │ reconcile │────▶│ usually: "nothing changed"   │
    └─────┬─────┘     └─────────────────────────────┘
          │
          ▼
    ┌───────────┐
    │  select   │◀─── (loop forever)
    └───────────┘

    On SIGINT/SIGTERM:
    "sitesd: received SIGTERM, shutting down" → clean exit

    On crash:
    systemd restarts after 10s (Restart=always)
    Next reconcile re-converges from actual state
    No lock files, no stale state, no corruption
```


## 6. Dota Integration — Deploy Key Lifecycle

```
    sites sync / sites deploy <domain>
          │
          │  site has deploy_key?
          │
     no ──┼──── yes
     │         │
     │         ▼
     │   ┌──────────────┐
     │   │  dota get     │    post-quantum vault
     │   │  <key-name>   │    (ML-KEM-768 + X25519)
     │   └──────┬───────┘
     │          │
     │          ▼
     │   ┌──────────────┐
     │   │ write key to │    /dev/shm/sites-keys/<random-hex>
     │   │ tmpfs (0600) │    (RAM-only on Linux)
     │   └──────┬───────┘
     │          │
     │          ▼
     │   ┌──────────────┐
     │   │ convert URL  │    https://github.com/user/repo
     │   │ HTTPS → SSH  │    → git@github.com:user/repo.git
     │   └──────┬───────┘
     │          │
     │          ▼
     │   ┌──────────────┐
     │   │ set env:     │    GIT_SSH_COMMAND="ssh -i <key>
     │   │ GIT_SSH_CMD  │      -o StrictHostKeyChecking=accept-new
     │   │              │      -o IdentitiesOnly=yes"
     │   └──────┬───────┘
     │          │
     ▼          ▼
    ┌──────────────────┐
    │  git clone/pull  │     (runs with or without SSH env)
    └────────┬─────────┘
             │
             ▼
    ┌──────────────────┐
    │ defer: os.Remove │     key destroyed immediately
    │ (key file)       │     (also runs on panic)
    └──────────────────┘

    Key properties:
    • Keys never touch persistent storage
    • Random filenames (crypto/rand, 8 bytes hex) prevent collisions
    • TOFU SSH model: accept on first use, reject on change
    • macOS fallback: os.TempDir() when /dev/shm unavailable
```


## 7. Atomic Write — Crash Safety

```
    generateCaddyfile(cfg)
          │
          ▼
    ┌──────────────┐
    │ diff against  │
    │ current file  │──── same? → skip (no-op)
    └──────┬───────┘
           │ different
           ▼
    ┌──────────────┐
    │ create tmp   │     /etc/caddy/sites.conf.tmp
    │ (same dir    │     same directory = same filesystem
    │  as target)  │     (avoids EXDEV on rename)
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │ write content │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │ f.Sync()     │     fsync: data on disk before rename
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │ f.Close()    │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │ os.Rename    │     atomic on POSIX
    │ tmp → target │     readers see old or new, never partial
    └──────────────┘

    On failure at any step:
    • tmp file cleaned up (or left as .tmp, harmless)
    • original sites.conf untouched
    • next reconcile re-converges
```


## 8. NixOS Integration — Minimal Touchpoints

```
    /etc/nixos/modules/
    ├── caddy.nix           ← existing, add one line:
    │                          import /etc/caddy/sites.conf
    │
    ├── sitesd.nix          ← new, ~15 lines:
    │   systemd.services.sitesd = {
    │     ExecStart = "${sites}/bin/sites watch";
    │     User = "sites";
    │     ProtectSystem = "strict";
    │     NoNewPrivileges = true;
    │     ReadWritePaths = [ "/var/lib/sites"
    │                        "/etc/caddy/sites.conf" ];
    │   };
    │
    └── (40+ other modules)   ← untouched


    That's it. Two touchpoints. Everything else is sites' problem.

    ┌─────────────────────────────────────────────────┐
    │                  NixOS manages:                  │
    │  • Caddy binary + TLS + hardening               │
    │  • sitesd systemd unit                           │
    │  • User/group creation                           │
    │  • Firewall rules                                │
    │  • dota binary + vault                           │
    │  • Everything else about the system              │
    └─────────────────────────────────────────────────┘
                          │
                          │ thin boundary
                          │
    ╔═════════════════════╧═══════════════════════════╗
    ║                  sites manages:                  ║
    ║  • Which domains exist                           ║
    ║  • Which repos they point to                     ║
    ║  • Deploy key extraction (dota → tmpfs → git)    ║
    ║  • Caddyfile generation                          ║
    ║  • Git clone/pull                                ║
    ║  • Deploy logging                                ║
    ╚═════════════════════════════════════════════════╝
```
