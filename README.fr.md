<div align="center">

# 🦀 Pingclair

**Un serveur web et reverse proxy moderne et performant, bâti sur Pingora**  
*La performance brute de Cloudflare Pingora, dans une enveloppe aussi minimaliste que Caddy*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-active-green.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/dorianverlaine/pingclair/pulls)

[English](README.md) · [繁體中文](README.zh-TW.md) · **Français**

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
*   ⚡ **HTTP/3 (QUIC) natif** — Une latence réduite et une meilleure migration de connexion sur les réseaux instables.
*   🔄 **Répartition de charge intelligente** — Plusieurs algorithmes intégrés (round-robin, least-connections, etc.), avec health checks et bascule automatique.
*   🔐 **HTTPS entièrement automatique** — Le support ACME intégré (Let's Encrypt) émet et renouvelle les certificats SSL/TLS sans aucune configuration.
*   📁 **Service de fichiers statiques performant** — Compression Gzip/Brotli, requêtes Range et transfert de fichiers efficace.
*   🔌 **Système de plugins modulaire** — *(en développement)* Étendez les fonctionnalités via des traits Rust, sans toucher au cœur.
*   📊 **Observabilité** — Export de métriques Prometheus et traçage OpenTelemetry prêts à l'emploi.

## ⚡ Benchmarks

La méthodologie complète, les résultats bruts et — surtout — les bugs mis au
jour par ce processus (dont un encore ouvert) se trouvent dans
[`benchmarks/README.md`](benchmarks/README.md) (en anglais). Le tableau
ci-dessous ne montre que les chiffres pour les fichiers statiques ; lisez
l'analyse complète avant d'en tirer des conclusions, en particulier sur le
débit du reverse proxy et la compression gzip sous charge.

**Environnement de test** : réseau bridge Docker, chaque serveur dans son
propre conteneur limité à 2 vCPU / 512 Mo, MacBook Pro (M2), `wrk -t4 -d15s`,
fichier statique de 1 Ko.

| Serveur | RPS @ c50 | RPS @ c500 | Remarques |
|---------|-----------|------------|-----------|
| **Nginx (Alpine)** | ~28 801 | ~27 853 | Le plus rapide à cette taille, à tous les niveaux de concurrence testés |
| **Pingclair (Debian)** | ~22 942 | ~21 162 | ~75-80 % de Nginx |
| **Caddy (Alpine)** | ~18 309 | ~18 448 | Constant, ~65 % de Nginx |

> **Des réserves plus importantes que le tableau**
> Sur le débit du reverse proxy, pingclair est passé devant nginx et caddy
> à forte concurrence dans cet environnement limité en conteneurs — un
> résultat réel mais non confirmé sur du matériel sans limitation, à ne
> pas généraliser. Plus important : un test de charge avec un gros fichier
> (20 Mo) compressé en gzip a révélé un bug réel et toujours ouvert : le
> chemin de compression des fichiers statiques de pingclair met en
> mémoire tampon le fichier entier à chaque requête, sans cache, et sous
> charge concurrente soutenue, un test de 20 secondes en a pris **16
> minutes** (sans plantage ni OOM — juste une mise en file d'attente
> sévère). Voir [`benchmarks/README.md`](benchmarks/README.md) pour le
> détail complet.

## 📦 Installation

### Prérequis

*   **Chaîne d'outils Rust** — Rust 1.85 ou plus récent.

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

Le Pingclairfile est un langage de configuration structuré. Il ressemble beaucoup à du Rust, mais il est conçu spécifiquement pour décrire le comportement du serveur.

### Structure de base

La configuration la plus simple se compose d'un ou plusieurs blocs de site :

```caddyfile
# Un serveur à l'écoute sur localhost
localhost:8080 {
    # Service de fichiers statiques
    file_server ./public
}
```

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
    # Proxy vers plusieurs backends
    reverse_proxy 10.0.0.1:8080 10.0.0.2:8080 {
        # Politique de répartition : round_robin, random, least_conn
        lb_policy least_conn

        # Nouvelle tentative en cas d'échec
        failover true
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
| **`pingclair-proxy`** | **Implémentation du proxy.** Logique de proxy HTTP/TCP bâtie sur le trait Proxy de Pingora, répartiteur de charge inclus. |
| **`pingclair-static`** | **Service de fichiers statiques.** Lecture de fichiers efficace, déduction du type MIME et transmission en flux. |
| **`pingclair-tls`** | **Gestion TLS.** Chargement des certificats, émission automatique via ACME (Let's Encrypt) et logique de handshake QUIC. |
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
