<div align="center">

# 🦀 Pingclair

**Un serveur web et reverse proxy moderne et performant, bâti sur Pingora**  
*La performance brute de Cloudflare Pingora, dans une enveloppe aussi minimaliste que Caddy*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-active-green.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/dorianverlaine/pingclair/pulls)

[English](README.md) · [繁體中文](README.zh.md) · **Français**

</div>

---

## 📖 Présentation

**Pingclair** est un serveur web et reverse proxy de nouvelle génération. Son idée directrice : reprendre la puissance de **Cloudflare Pingora** — le framework de proxy en Rust qui traite des milliers de milliards de requêtes — et l'envelopper dans une couche aussi accessible que **Caddy**.

La configuration de Nginx est réputée absconse, tandis que Caddy est agréable à utiliser mais repose sur Go. Pingclair vient combler ce vide : **100 % Rust**, **sûr en mémoire**, **performant** et **intuitif à configurer**.

Que vous ayez besoin d'un simple serveur de fichiers statiques ou d'une passerelle d'entreprise avec répartition de charge, HTTPS automatique et HTTP/3, Pingclair fait le travail.

## ✨ Fonctionnalités

*   🚀 **Propulsé par Pingora** — Sur les épaules d'un géant : l'infrastructure éprouvée de Cloudflare, pour une stabilité et un débit de niveau entreprise.
*   🔒 **Sûreté mémoire** — Rust élimine les débordements de tampon et, plus largement, toute la classe des vulnérabilités mémoire classiques.
*   📝 **Configuration compatible Caddyfile** — Un DSL de configuration minimaliste, avec **HTTPS automatique**, **écouteurs multiples** et **matchers nommés**, compatible avec la syntaxe Caddyfile courante.
*   ⚡ **HTTP/3 (QUIC) natif** — Bâti sur [quiche](https://github.com/cloudflare/quiche), la pile QUIC de production qui fait tourner l'edge de Cloudflare. Une latence réduite et une meilleure migration de connexion sur les réseaux instables.
*   🔄 **Répartition de charge intelligente** — Plusieurs algorithmes intégrés (round-robin, least-connections, etc.), avec health checks et bascule automatique.
*   🔐 **HTTPS entièrement automatique** — Le support ACME intégré (Let's Encrypt) émet et renouvelle les certificats SSL/TLS sans aucune configuration.
*   📁 **Service de fichiers statiques performant** — Compression Gzip/Brotli, requêtes Range et transfert de fichiers efficace.
*   📊 **Observabilité** — Export de métriques Prometheus et traçage OpenTelemetry prêts à l'emploi.

## ⚡ Benchmarks

La méthodologie complète, les résultats bruts et — surtout — les bugs mis au
jour et corrigés par ce processus se trouvent dans
[`benchmarks/README.md`](benchmarks/README.md) (en anglais). Lisez l'analyse
complète avant d'en tirer des conclusions.

**Environnement de test** : VPS bare-metal (Aliyun, 2 vCPU / 1,6 Go,
Ubuntu 24.04), chaque serveur à tour de rôle sur `127.0.0.1:8080`,
`wrk -t2 -d15s` en loopback (`results/20260725_vps_onbox/`).

| Scénario | Pingclair | Nginx | Caddy |
|----------|-----------|-------|-------|
| Statique 1 Ko, brut (c100) | 50 145 req/s | **53 579 req/s** | 17 337 req/s |
| Statique 1 Ko, gzip (c100) | **42 982 req/s** | 42 510 req/s | 15 302 req/s |
| Reverse proxy (c100) | 20 154 req/s | **21 961 req/s** | 9 870 req/s |
| Gros fichier 20 Mo, gzip (c20) | **703 req/s, 0 timeout** | 9,1 req/s, 110 timeouts | 10,1 req/s, 65 timeouts |

**Comment lire ces chiffres**

- Le petit fichier statique est désormais quasiment à égalité avec nginx
  (94 % en brut, 101 % en gzip) et ~2,9x devant Caddy. Il n'en a pas
  toujours été ainsi : les mesures précédentes montraient un écart de
  ~2,9x avec nginx, dont la cause était `tokio::fs` — chaque appel est
  un aller-retour inter-threads `spawn_blocking`, soit ~8 futex par
  requête. Le chemin chaud statique utilise maintenant `std::fs`
  synchrone (le modèle nginx : les lectures de fichiers locaux ne
  bloquent pas vraiment), ce qui a fait passer les futex de 8/requête à
  ~0 et le débit de 18,7k à 50k req/s. Détails dans
  `benchmarks/README.md`.
- Le reverse proxy atteint ~92 % de nginx et ~2x Caddy, sans aucune
  erreur pour les trois.
- Les gros fichiers compressibles sont le terrain de prédilection du
  cache de corps compressés : ~70x le débit de nginx/caddy avec **0
  timeout**, car les accès répétés sautent entièrement la compression
  alors que nginx et caddy recompressent le fichier de 20 Mo à chaque
  requête. Ce cache coûte de la mémoire par conception (pic RSS de 74
  Mio contre 21 Mio pour nginx — budget borné à 64 Mo).
- Les niveaux de compression ne sont pas parfaitement alignés entre
  moteurs (`gzip_comp_level 1` pour nginx, défauts ailleurs) : les
  comparaisons gzip sont indicatives, pas exactes.

Un run Docker bridge plus ancien (conteneurs 2 vCPU / 512 Mo, Apple M2),
avec la matrice complète et la liste des **20 bugs trouvés et corrigés
grâce aux benchmarks** — dont un bug de compression statique qui
transformait un test de 20 secondes en 16 minutes — est documenté dans
[`benchmarks/README.md`](benchmarks/README.md).

## 📦 Installation

### Prérequis

*   **Chaîne d'outils Rust** — Rust 1.88 ou plus récent.

### Compilation depuis les sources

La compilation depuis les sources est recommandée : elle produit un binaire optimisé pour votre processeur.

```bash
# 1. Cloner le dépôt
git clone https://github.com/dorianverlaine/pingclair.git
cd pingclair

# 2. Compiler et installer (mode release)
cargo install --path ./pingclair
```

Une fois l'installation terminée, la commande `pingclair` est disponible dans votre `PATH`.

### Installation en une ligne sur Ubuntu/Debian (recommandé)

Sous Ubuntu ou Debian, vous pouvez utiliser le script d'installation. Il télécharge (ou compile) le binaire, met en place un service `systemd` et crée un utilisateur `pingclair` non privilégié, autorisé à se lier aux ports bas via `setcap`.

```bash
# Exécuter le script d'installation (droits sudo requis)
curl -fsSL https://raw.githubusercontent.com/dorianverlaine/pingclair/main/scripts/install.sh | sudo bash
```

Après l'installation, la commande `pc` (abréviation de `pingclair`) permet de gérer le service.

## 🏃 Démarrage rapide

Pingclair propose deux modes d'exécution : le **mode CLI**, pratique pour les tests rapides, et le **mode fichier de configuration**, destiné à la production.

### 1. Mode CLI

**Servir des fichiers statiques**  
Exposer le répertoire courant en HTTP sur le port 8080 :
```bash
pingclair file-server --listen :8080 --root .
```

**Lancer un reverse proxy**  
Rediriger le trafic du port local 8080 vers un backend sur le port 3000 :
```bash
pingclair reverse-proxy --from :8080 --to localhost:3000
```

**Gérer le service système (Linux)**  
Après installation, les commandes intégrées pilotent l'unité `systemd` :
```bash
pc service start    # démarrer
pc service stop     # arrêter
pc service status   # état
pc service reload   # rechargement à chaud de la configuration (SIGHUP)
pc service restart  # redémarrer
```

### 2. Mode fichier de configuration (recommandé)

Créez un fichier nommé `Pingclairfile` à la racine du projet, puis lancez :

```bash
pingclair run Pingclairfile
```

## 🛠️ Configuration (Pingclairfile)

Le DSL Pingclair est un langage de configuration structuré conçu pour décrire le comportement du serveur. Comme le `Caddyfile` de Caddy, son nom de fichier conventionnel est `Pingclairfile`.

### Structure de base

La configuration la plus simple se compose d'un ou plusieurs blocs de site :

```caddyfile
# Un serveur à l'écoute sur localhost
localhost:8080 {
    # Service de fichiers statiques
    file_server ./public
}
```

Lorsque Pingclair se trouve derrière un load balancer ou un CDN que vous
administrez, déclarez uniquement ces réseaux mandataires dans le bloc global.
Un pair non approuvé ne peut pas fournir l'identité via `X-Forwarded-For`,
`X-Real-IP` ou `X-Forwarded-Proto` :

```caddyfile
{
    trusted_proxies 10.0.0.0/8 2001:db8::/32
}
```

Le contrôle d'accès, le rate limiting, l'IP-hash, les en-têtes transmis, les
placeholders et les journaux d'accès partagent la même adresse client
vérifiée. La modification de `trusted_proxies` nécessite actuellement un
redémarrage.

### Routage et matchers

Pingclair dispose d'un système de matchers puissant : routez les requêtes selon le chemin, le domaine, les en-têtes, etc.

```caddyfile
example.com {
    # 1. Un matcher nommé pour les chemins d'API
    @api {
        path /api/v1/*
    }

    # Logique propre aux requêtes API
    handle @api {
        header {
            set Content-Type "application/json"
        }
        reverse_proxy localhost:3000
    }

    # 2. Correspondance des ressources statiques
    handle /assets/* {
        header {
            set Cache-Control "public, max-age=86400"
        }
        file_server ./assets
    }

    # 3. Repli par défaut (fallback)
    handle {
        respond "Page Not Found" 404
    }
}
```

### Fonctionnalité avancée : les macros

C'est l'une des fonctionnalités les plus puissantes de Pingclair. Définissez une macro pour encapsuler un fragment de configuration récurrent, puis réutilisez-le entre plusieurs serveurs ou routes afin de garder une configuration concise (principe DRY).

```rust
// Une macro qui ajoute des en-têtes de sécurité
macro security_headers!() {
    headers {
        remove: ["Server", "X-Powered-By"];
        set: {
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000",
        };
    }
}

// Une macro de journalisation commune
macro standard_log!(path) {
    log {
        output: File(path);
        format: Json;
        level: Info;
    }
}

server "blog.example.com" {
    listen: "0.0.0.0:443";

    // Utilisation des macros
    use security_headers!();
    use standard_log!("/var/log/pingclair/blog.log");

    route {
        _ => { file_server "./blog"; }
    }
}

server "shop.example.com" {
    listen: "0.0.0.0:443";

    // Réutilisation de la même configuration de sécurité
    use security_headers!();
    use standard_log!("/var/log/pingclair/shop.log");

    route {
        _ => { proxy "http://shop-backend:8000"; }
    }
}
```

### Reverse proxy et répartition de charge

```caddyfile
:80 :8080 {
    reverse_proxy {
        lb_policy least_conn
        to 10.0.0.1:8080 { weight 3 }
        to 10.0.0.2:8080
        # Utilisé seulement quand tous les backends principaux sont indisponibles.
        to 10.0.0.3:8080 { backup }
    }
}
```

### Contrôles de parité Caddy

```caddyfile
example.com {
    error_page 404 /srv/errors/404.html

    @legacy path /legacy/*
    redir @legacy https://example.com/new permanent

    handle /api/* {
        cors https://app.example.com {
            methods GET POST
            allow_credentials
        }
        access_control {
            allow_ip 10.0.0.0/8
            deny_user_agent "(?i)bot"
        }
        # Les captures regex utilisent $1, $2, ... ; la query string est préservée.
        rewrite "^/api/(.*)$" "/v1/$1"
        reverse_proxy 127.0.0.1:3000
    }
}
```

## 🏗️ Architecture

Pingclair est organisé en workspace Cargo modulaire :

| Crate (module) | Description |
|----------------|-------------|
| **`pingclair`** | **Point d'entrée CLI.** Analyse les arguments, initialise la journalisation, amorce le système. |
| **`pingclair-core`** | **Cœur d'exécution.** Structures de données, traits et gestion du cycle de vie du serveur. |
| **`pingclair-config`** | **Compilateur de configuration.** Analyse lexicale, syntaxique et sémantique du `Pingclairfile`, puis génération des objets de configuration d'exécution. |
| **`pingclair-proxy`** | **Implémentation du proxy.** Logique de proxy HTTP/TCP bâtie sur le trait Proxy de Pingora, répartiteur de charge inclus, ainsi que l'écouteur HTTP/3 (QUIC) bâti sur quiche de Cloudflare. |
| **`pingclair-static`** | **Service de fichiers statiques.** Lecture de fichiers efficace, déduction du type MIME et transmission en flux. |
| **`pingclair-tls`** | **Gestion TLS.** Chargement des certificats et émission automatique via ACME (Let's Encrypt). |
| **`pingclair-api`** | **API d'administration.** Interface RESTful pour consulter l'état ou recharger la configuration à chaud, à l'exécution. |
| **`pingclair-plugin`** | **Système de plugins.** Définit l'interface permettant aux développeurs tiers d'étendre les fonctionnalités. |

## 🤝 Contribuer

Les contributions sont les bienvenues — qu'il s'agisse de corriger un bug, d'ajouter une fonctionnalité ou simplement d'améliorer la documentation.

### Processus

1.  **Forkez** le dépôt.
2.  **Créez une branche** : `git checkout -b feature/my-cool-feature`
3.  **Écrivez le code** en respectant le style Rust standard.
4.  **Lancez les tests** et assurez-vous qu'ils passent :
    ```bash
    cargo test --workspace
    ```
5.  **Ouvrez une PR** en décrivant votre modification.

## 📄 Licence

Ce projet est distribué sous **licence Apache 2.0**. Voir le fichier [LICENSE](LICENSE) pour les détails.

---

<div align="center">
  <sub>Conçu avec ❤️ et Rust</sub>
</div>
