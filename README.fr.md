<div align="center">

<img src="assets/logo.png" alt="Pingclair" width="520">

**Un serveur web et reverse proxy moderne et performant, bâti sur Pingora**  
*La performance brute de Cloudflare Pingora, dans une enveloppe aussi minimaliste que Caddy*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-pingclair.com-blue.svg)](https://pingclair.com)
[![Rust](https://img.shields.io/badge/rust-1.98%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-active-green.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/dorianverlaine/pingclair/pulls)

[English](README.md) · [中文](README.zh.md) · **Français**

</div>

---

## 📖 Présentation

**Pingclair** est un serveur web et reverse proxy de nouvelle génération. Son idée directrice : reprendre la puissance de **Cloudflare Pingora** — le framework de proxy en Rust qui traite des milliers de milliards de requêtes — et l'envelopper dans une couche aussi accessible que **Caddy**.

La configuration de Nginx est réputée absconse, tandis que Caddy est agréable à utiliser mais repose sur Go. Pingclair vient combler ce vide : **100 % Rust**, **sûr en mémoire**, **performant** et **intuitif à configurer**.

Que vous ayez besoin d'un simple serveur de fichiers statiques ou d'une passerelle d'entreprise avec répartition de charge, HTTPS automatique et HTTP/3, Pingclair fait le travail.

La documentation publiée — installation, référence du Pingclairfile et
méthodologie des benchmarks — se trouve sur <https://pingclair.com>.

## ✨ Fonctionnalités

*   🚀 **Propulsé par Pingora** — Sur les épaules d'un géant : l'infrastructure éprouvée de Cloudflare, pour une stabilité et un débit de niveau entreprise. Les écouteurs en clair acceptent HTTP/1.1 et h2c en connaissance préalable ; les écouteurs TLS négocient HTTP/2 par ALPN.
*   🔒 **Sûreté mémoire** — Rust élimine les débordements de tampon et, plus largement, toute la classe des vulnérabilités mémoire classiques.
*   📝 **Configuration compatible Caddyfile** — Un DSL de configuration minimaliste, avec **HTTPS automatique**, **écouteurs multiples** et **matchers nommés**, compatible avec la syntaxe Caddyfile courante.
*   ⚡ **HTTP/3 (QUIC) natif** — Bâti sur [quiche](https://github.com/cloudflare/quiche), la pile QUIC de production qui fait tourner l'edge de Cloudflare. Une latence réduite et une meilleure migration de connexion sur les réseaux instables. Une configuration `tls` explicite active HTTPS et H3 sur n'importe quel port d'écoute ; 443 et 8443 restent reconnus automatiquement. Les trailers de requête déclarés ne sont transférés par aucun protocole aval : Pingclair renvoie `501` avant l'envoi de la réponse ou réinitialise un flux H3 déjà engagé. Une réponse amont annonçant des trailers renvoie `502` tant que leur transfert de bout en bout n'est pas pris en charge. Pingclair est un reverse proxy et n'ouvre aucun tunnel : `CONNECT` reçoit `405` avec `Allow` sur tous les protocoles, et le CONNECT étendu n'est jamais proposé. Sans SNI, le client reçoit le certificat désigné par `default_sni` pour ce point d’écoute ; sans valeur configurée, la négociation est refusée. Un nom explicite inconnu ne reçoit jamais le certificat d’un autre site.
*   🔄 **Répartition de charge intelligente** — Plusieurs algorithmes intégrés (round-robin, least-connections, etc.), avec health checks et bascule automatique.
*   🔐 **HTTPS automatique et privé** — ACME intégré (Let's Encrypt) émet les certificats publics, tandis que `tls internal` fournit une autorité locale persistante pour les origines privées et les tunnels.
*   📁 **Service de fichiers statiques performant** — Compression Gzip et Zstandard, requêtes Range (y compris `416` quand la plage ne peut pas être satisfaite) et transfert de fichiers efficace. Brotli **n'est pas** implémenté : `encode br` est refusé par son nom, comme par un build Caddy standard.
*   📊 **Observabilité** — Export de métriques Prometheus prêt à l'emploi.

## ⚡ Benchmarks

Comparaison la plus récente : Pingclair `v0.2.0-rc.3` (le binaire publié)
contre nginx 1.31.6 et Caddy 2.11.4, mesurée sur un portable Apple M2 avec
OrbStack. Chaque candidat tourne dans un conteneur limité à **2 CPU** avec le
même nombre de workers et la même charge utile de 1 Kio ; le backend du
reverse proxy vit dans son propre conteneur sur le même réseau Docker et le
générateur de charge tourne nativement. HTTP/1.1, HTTPS/1.1 et HTTP/2
utilisent `h2load` en natif ; HTTP/3 utilise le `h2load` ngtcp2 dans le même
réseau. Chaque valeur est la médiane de trois passes entrelacées de 50 000
requêtes, et une ligne ne compte que si toutes les requêtes ont réussi.

| Scénario | Pingclair | nginx 1.31.6 | Caddy 2.11.4 |
| --- | ---: | ---: | ---: |
| HTTP/1.1 statique | 46 125 | 39 478 | 18 266 |
| HTTPS/1.1 statique | 40 721 | 31 508 | 19 978 |
| HTTP/2 statique | 92 369 | 41 972 | 17 424 |
| HTTP/3 statique | 56 180 | 55 638 | 22 912 |
| Reverse proxy HTTP/1.1 | 20 856 | 22 584 | 17 117 |
| Reverse proxy HTTPS/1.1 | 20 297 | 21 944 | 16 660 |
| Reverse proxy HTTP/2 | 23 181 | 20 396 | non terminé |
| Reverse proxy HTTP/3 | 28 078 | 22 213 | non terminé |

Pingclair est en tête sur les lignes statiques HTTP/1.1, HTTPS/1.1 et HTTP/2
(1,2×, 1,3× et 2,2× respectivement), tandis que HTTP/3 est pratiquement à
égalité. Sur le reverse proxy, il devance nginx de 14 % en HTTP/2 et de 26 % en
HTTP/3, alors que HTTP/1.1 et HTTPS/1.1 restent environ 8 % derrière.

Sur cette machine et avec ce harnais, Caddy n'a pas terminé les lignes proxy
HTTP/2 et HTTP/3, car le renouvellement de ses connexions amont a épuisé les
ports éphémères disponibles du conteneur à la concurrence testée ; ces cellules
sont donc signalées comme incomplètes plutôt que comparées sous une autre
charge. Les requêtes par seconde absolues sur un portable ne constituent pas
une revendication de capacité ; ces ratios ne décrivent la performance relative
que dans le cadre de cette charge contrôlée, et chaque ligne ne vaut que pour
une comparaison **entre serveurs d'un même protocole** : le générateur de
charge HTTP/3 s'exécutant dans un autre environnement, les débits absolus ne
doivent pas être comparés d'un protocole à l'autre.

## 📦 Installation

### Prérequis

*   **Chaîne d'outils Rust** — Rust 1.98 ou plus récent.

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

### Installation en une ligne sur Linux

> 📦 **L'installation par défaut est `v0.2.0-rc.3`, une version candidate.**
> C'est délibérément ce que `releases/latest` désigne désormais : `v0.1.7` est
> antérieure à la parité HTTP/3, au TLS mutuel, à l'API d'administration et à la
> plupart des corrections de sécurité listées dans
> [`CHANGELOG.md`](CHANGELOG.md), et n'est pas une version par laquelle
> commencer. Les
> [notes de version](https://github.com/dorianverlaine/pingclair/releases/tag/v0.2.0-rc.3)
> portent ce qui a changé dans cette candidate et les défauts connus au moment
> du tag. Le script affiche l'étiquette qu'il installe et vérifie la somme de
> contrôle SHA-256 publiée avant de décompresser.
>
> 🪦 **`v0.1.x` n'est plus maintenue.** Il n'y aura pas de `v0.1.8` : aucune
> correction, aucun rétroportage et aucun avis de sécurité pour cette branche.
> Rester dessus, c'est rester sur une version que personne ne corrigera. L'une
> des raisons de migrer : son API d'administration n'authentifiait rien — une
> configuration `v0.1.x` analysait `api_key` puis ne la lisait jamais, donc ce
> champ ne protégeait rien. Si vous exploitez `v0.1.7`, migrez.

Sur n'importe quelle distribution Linux, le script d'installation fonctionne : il télécharge (ou compile) le binaire, met en place un service `systemd` et crée un utilisateur `pingclair` non privilégié, autorisé à se lier aux ports bas via `setcap`. Après l'installation, la commande `pc` (abréviation de `pingclair`) permet de gérer le service.

```bash
# Exécuter le script d'installation (droits sudo requis)
curl -fsSL https://pingclair.com/install.sh | sudo bash
```

Le script accepte un drapeau pour suivre `main` au lieu de la version stable.
Cloner main et le compiler localement (nécessite Rust 1.98+) :

```bash
curl -fsSL https://pingclair.com/install.sh | sudo bash -s -- --main
```

### Déploiement de production avec Docker Compose

Pour un déploiement conteneurisé, lancez le mode fichier de configuration et
conservez le magasin TLS sur un volume persistant (certificats, comptes ACME
et CA interne y sont stockés) :

```yaml
services:
  pingclair:
    image: ghcr.io/dorianverlaine/pingclair:latest
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"   # HTTP/3
    volumes:
      - ./conf:/etc/pingclair:ro
      - ./site:/srv
      - pingclair_tls:/var/lib/pingclair/.local/share/pingclair
    command: ["pingclair", "run", "/etc/pingclair/Pingclairfile"]

volumes:
  pingclair_tls:
```

Placez votre `Pingclairfile` dans `./conf/` et vos fichiers statiques dans
`./site/` (référencez-les avec `root /srv`). HTTPS, redirection HTTP et
HTTP/3 se comportent comme sur un hôte.

### Faire confiance à la racine `tls internal`

La CA locale persistante publie sa racine dans
`$PINGCLAIR_TLS_STORE/pki/authorities/local/root.crt` (dans un conteneur :
`docker compose cp pingclair:/var/lib/pingclair/.local/share/pingclair/pki/authorities/local/root.crt
./root.crt`). Installez-la dans le magasin de confiance système (Linux :
`update-ca-certificates` ; macOS : `security add-trusted-cert`) ou importez-la
manuellement dans les navigateurs à magasin propre (Firefox, Chrome). À ne
faire que pour des origines que vous contrôlez.

### Où le dépôt TLS range ses fichiers

L'arborescence est celle de Caddy : une sauvegarde, un rapport d'expiration ou
un inventaire de certificats écrit pour un répertoire de données Caddy lit
celui-ci de la même façon.

```
<pki>        pki/authorities/local/root.crt          certificat racine
             pki/authorities/local/root.key          clé privée racine
             pki/authorities/local/intermediate.crt  certificat de signature
             pki/authorities/local/intermediate.key  clé privée de signature
certificates/local/<site>/<site>.crt                   chaîne feuille
certificates/local/<site>/<site>.key                   clé privée feuille
certificates/local/<site>/<site>.json                  noms couverts, non secret
```

Un site à joker est rangé sous l'orthographe qu'en donne Caddy : `*.example.com`
devient `certificates/local/wildcard_.example.com/`.

📌 **Mise à niveau depuis un dépôt écrit avant cette arborescence.** L'ancien
arbre `internal/` n'est ni lu ni migré, et c'est délibéré. Au démarrage suivant,
le serveur ne trouve plus d'autorité là où il cherche désormais, en crée une
nouvelle et réémet les certificats dont il a besoin. Il journalise un
avertissement lorsqu'il trouve l'ancien arbre, pour que le changement ne soit pas
silencieux. Chaque client qui faisait
confiance à l'ancienne racine doit recevoir la nouvelle — les commandes
ci-dessus sont cette étape. Si votre configuration obtient aussi des certificats
auprès d'une AC publique, leur réémission est décomptée de ses limites de débit.

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
pc service reload   # rechargement à chaud de la configuration (SIGUSR1)
pc service restart  # redémarrer
```

### 2. Mode fichier de configuration (recommandé)

Créez un fichier nommé `Pingclairfile` à la racine du projet, puis lancez :

```bash
pingclair run Pingclairfile
```

`run` sans argument cherche `Pingclairfile` dans le répertoire courant, puis
`Caddyfile`, pour qu'une configuration migrée fonctionne sans option. Si aucun
des deux n'existe, **le processus se termine avec le code 1** et le message
nomme les deux candidats ainsi que le répertoire parcouru.

📌 C'est une différence délibérée avec Caddy : `caddy run` sans configuration
démarre un serveur vide et attend que l'Admin API lui en fournisse une. Cela
convient à l'orchestration qui démarre un processus puis lui envoie sa
configuration. Ici le démarrage est refusé, parce qu'un opérateur qui a tapé
`run` dans le mauvais répertoire reçoit une erreur plutôt qu'un serveur qui ne
sert rien en silence. Si vous avez besoin du comportement de Caddy, démarrez
avec une configuration minimale puis chargez la vraie via l'Admin API.

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

### HTTPS automatique pour les noms publics

`tls auto` obtient et renouvelle un certificat public via ACME (Let's Encrypt).
Aucun `listen` n'est nécessaire :

```caddyfile
{
    email admin@example.com
}

example.com {
    tls auto
    reverse_proxy app:8080
}
```

C'est toute la configuration. Un site avec TLS et sans `listen` sert HTTPS sur
443, et Pingclair provisionne un second listener, en clair, sur le port 80. Il
remplit deux rôles : répondre au challenge HTTP-01 d'ACME — que l'autorité
récupère en HTTP **en clair** sur ce port précis (RFC 8555 §8.3) — et rediriger
toute autre requête vers HTTPS avec un 308. Le port 80 reste donc non chiffré
même dans un bloc qui configure TLS : un listener TLS y rejetterait la sonde en
clair de l'autorité et aucun certificat ne pourrait être émis.

Le comportement se pilote depuis le bloc global :

| `auto_https` | Effet |
| --- | --- |
| `on` (par défaut) | Provisionne le port 80, répond aux challenges ACME, redirige vers HTTPS. |
| `disable_redirects` | Provisionne le port 80 et répond aux challenges ACME, sans rediriger. |
| `off` | Ne provisionne rien ; la gestion des certificats est également désactivée. |

Écrire votre propre `listen :80` dans le bloc désactive le listener automatique :
Pingclair sert alors ce port exactement comme configuré. Si le port 80 ne peut
pas être lié (déjà utilisé, ou privilèges insuffisants), le listener automatique
est ignoré avec un avertissement et HTTPS continue de servir ; la validation
HTTP-01 d'ACME, elle, ne fonctionnera pas.

Une adresse qui nomme un port sans schéma est servie en **HTTPS** : un listener
qui n'est pas sur le port HTTP n'est pas un listener en clair, et c'est la règle
qu'applique l'implémentation de référence. `secure.example:8443` obtient donc un
certificat automatique, exactement comme `secure.example`. `http://` devant
l'adresse est la façon de demander le clair, sur n'importe quel port, et
`tls off` fonctionne aussi. Deux sites qui partagent un port doivent s'accorder
sur TLS, sinon la configuration est refusée plutôt que l'un des deux l'emportant
en silence.

Un même bloc peut mélanger des schémas explicites, par exemple
`http://example.com, https://example.com { … }`. Pingclair partage les handlers
mais conserve une politique indépendante par listener : HTTP reste en clair et
sert la route configurée, tandis que HTTPS obtient toujours son certificat
automatique. Les noms d'hôte restent également correctement isolés lorsque les
adresses HTTP et HTTPS diffèrent. `tls off` reste prioritaire même sur le port
443.

Le certificat installé inclut les intermédiaires émis par l'autorité. Un serveur
qui n'envoie que son certificat feuille semble fonctionner dans un navigateur —
les navigateurs mettent les intermédiaires en cache et récupèrent les manquants
via AIA — alors que `curl`, Go et Java le rejettent sans appel.

Pour rediriger à la main, `redir` développe `{host}` et `{uri}`. Mettez la cible
entre guillemets pour que `{` ne soit pas lu comme un début de bloc :

```caddyfile
http://example.com {
    redir "https://{host}{uri}" 308
}
```

### TLS interne pour les origines privées

Utilisez `tls internal` lorsque le client TLS est un tunnel, un load balancer
ou un service privé de confiance et que la validation ACME publique est
indisponible :

```caddyfile
https://origin.example.test:6688 {
    tls internal
    reverse_proxy app:8080
}
```

Pingclair conserve une autorité locale valable dix ans et des certificats
leaf renouvelables de 90 jours sous `PINGCLAIR_TLS_STORE` — un binaire nu
utilise `$XDG_DATA_HOME/pingclair` (`~/.local/share/pingclair`), l'image
conteneur `/var/lib/pingclair/.local/share/pingclair`. Les clients qui vérifient l'origine
doivent faire
confiance à `$PINGCLAIR_TLS_STORE/pki/authorities/local/root.crt` ; les clés
privées de l'autorité restent dans `root.key` et `intermediate.key`, à côté,
lisibles uniquement par leur propriétaire. H1/H2 et H3 utilisent le même
certificat leaf persistant.
`tls internal` exige un nom de site concret et ne peut pas être combiné avec
`tls auto`, un email ACME ou des chemins de certificat manuels.

L'option globale `local_certs` applique le même choix à chaque site sans
gestion de certificats propre : toute l'automatisation par défaut utilise
l'autorité locale persistante au lieu de l'ACME public.

L'emplacement de ce dépôt est une décision de configuration : l'option globale
`storage file_system <path>` nomme le répertoire, et elle prime sur
`PINGCLAIR_TLS_STORE` et sur la convention de la plateforme. Seul le module
fichier est implémenté — un backend distant ou partagé est refusé par son nom
plutôt qu'accepté, parce que l'accepter laisserait le dépôt où il est tout en
donnant l'impression qu'il a déménagé. Le chemin résolu est journalisé au
démarrage : deux déploiements qui nomment des dépôts différents créent deux
racines de confiance distinctes, sans autre différence visible.

Ce build n'effectue aucun agrafage OCSP. L'option globale `ocsp_stapling off`
est acceptée parce qu'elle nomme exactement cet état, et une ligne au démarrage
le dit lorsqu'elle est écrite ; `on` et l'option nue sont refusées, puisqu'elles
demanderaient un agrafage qui n'existe pas ici. (Caddy refuse également ces deux
orthographes, donc rien de ce qui se charge en amont n'est écarté ici.)

Lorsque Pingclair se trouve derrière un load balancer ou un CDN que vous
administrez, déclarez uniquement ces réseaux mandataires dans le bloc global.
Un pair non approuvé ne peut pas fournir l'identité via `X-Forwarded-For`,
`X-Real-IP` ou `X-Forwarded-Proto` :

```caddyfile
{
    trusted_proxies 10.0.0.0/8 2001:db8::/32
}

example.com {
    listen :8443 proxy_protocol
    reverse_proxy app:8080
}
```

Le contrôle d'accès, le rate limiting, l'IP-hash, les en-têtes transmis, les
placeholders et les journaux d'accès partagent la même adresse client
vérifiée. La modification de `trusted_proxies` nécessite actuellement un
redémarrage. `listen … proxy_protocol` exige PROXY v1 ou v2 sur chaque connexion TCP
et rejette avant TLS ou HTTP tout pair de transport absent de
`trusted_proxies`. Les chaînes XFF et RFC 7239 `Forwarded` sont bornées ; une
syntaxe invalide ou des identités contradictoires échouent en mode fermé.
PROXY protocol ne s'applique pas au listener HTTP/3 UDP.

`servers { listener_wrappers { proxy_protocol } }` est l'orthographe Caddy pour
« chaque listener que cette Caddyfile déclare », et elle est acceptée comme
telle ; `listen … proxy_protocol` reste la façon d'exiger l'en-tête sur un seul
listener. Seule la forme sans adresse est acceptée : `servers <address> { … }`
est refusé, parce que ce build applique les options d'un bloc `servers` à chaque
listener et que l'en-tête sur un port dont les clients ne l'envoient pas les
rejette tous. Les deux orthographes signifient ici la même chose, et c'est la
stricte : le `proxy_protocol { fallback_policy require }` d'en amont, où une
connexion sans en-tête est refusée plutôt que servie.

#### Bloquer des adresses clientes

🚫 Pour refuser une plage de clients, nommez-la avec un matcher `client_ip` et
appliquez-lui `abort`, exactement comme dans Caddy. Une requête qui correspond
ne reçoit aucune réponse : la connexion est fermée en HTTP/1.1 et HTTP/2, et
seul le flux de cette requête est réinitialisé en HTTP/3.

```caddyfile
example.com {
    @blocked client_ip 203.0.113.0/24 2001:db8::/32
    abort @blocked

    respond "hello"
}
```

`client_ip` compare l'adresse client vérifiée décrite plus haut : derrière un
proxy listé dans `trusted_proxies`, c'est le client transmis, et pour tout
autre pair c'est le pair de la socket ; un `X-Forwarded-For` forgé ne peut donc
ni faire entrer ni faire sortir un client du blocage. 📌 Le `remote_ip` de Caddy
désigne toujours le pair de la socket ; ici il compare pour l'instant la même
adresse vérifiée que `client_ip`, donc écrivez `client_ip` quand vous visez le
client. Une Pingclairfile n'a pas de liste de blocage globale, parce que Caddy
n'en a pas ; le champ `blocked_ips` n'existe que dans la configuration JSON et
coupe une connexion dont le pair de la socket correspond, HTTP/3 compris, avant
toute lecture TLS ou HTTP.

### Limites de ressources et délais

**Il n'y a pas de plafond de corps de requête, sauf si la configuration en
demande un** — c'est ce que fait Caddy. Un site qui en veut un écrit
`request_body { max_size <size> }` au niveau du site, ou sur la route qui
accepte les téléversements (le champ JSON correspondant est
`client_max_body_size`, qui n'a pas d'orthographe Caddyfile) ; `0` signifie
aucune limite. Un corps au-delà du plafond configuré est refusé par un `413` sur
le segment qui le franchit.

Les limites en aval se configurent au niveau du site, et les phases de délai
amont dans `reverse_proxy`. Une durée exige une unité. Les WebSocket upgrades,
`flush_interval -1` et `text/event-stream` utilisent les paramètres de connexion
longue ; `off` supprime explicitement le délai correspondant.

```caddyfile
example.com {
    limits {
        header_timeout 5s
        body_timeout 30s
        idle_timeout 30s
        request_timeout 2m
        max_headers 100
        max_header_bytes 65536
        max_connections 10000
        upload_bytes_per_sec 10485760
        download_bytes_per_sec 52428800
        long_connections {
            idle_timeout 5m
            request_timeout off
        }
    }

    reverse_proxy app:8080 {
        retry {
            max_attempts 4
            total_timeout 2s
            backoff 50ms
            status_codes 429 502 503 504
            methods GET HEAD
        }
        overload {
            max_in_flight 256
            max_pending 64
            pending_timeout 250ms
            upstream_max_connections 64
        }
        circuit_breaker {
            consecutive_failures 5
            error_rate_percent 50
            minimum_requests 20
            window_requests 100
            open_for 30s
            half_open_requests 1
            failure_statuses 429 502 503 504
        }
        transport http {
            connect_timeout 3s
            first_byte_timeout 30s
            between_reads_timeout 15s
        }
    }
}
```

`max_attempts` inclut la première tentative. Un échec de connexion peut être
retenté sans risque, puisqu'aucun octet de la requête n'a atteint ce backend.
Une nouvelle tentative déclenchée par le statut exige une méthode idempotente
configurée et une requête réellement sans body ; Pingclair ne met jamais un
body en mémoire tampon et ne le rejoue pas pour cette politique. Sans bloc
`retry`, la limite historique de repli après échec de connexion est conservée
et aucun statut de réponse n'est retenté.

`max_in_flight` borne le travail en cours dans la route et `max_pending` ajoute
une file d'attente bornée. Une file pleine échoue immédiatement avec 429 ; une
attente expirée renvoie 503. `upstream_max_connections` est une limite
conservatrice des requêtes occupant chaque backend ; elle borne aussi le
multiplexage H2 au lieu de prétendre compter les sockets physiques. Chaque
backend concret possède son propre circuit breaker. Il s'ouvre dès qu'un des
seuils configurés est atteint, répond rapidement 503, puis n'admet que le
nombre configuré de sondes half-open après `open_for`. Sans
`failure_statuses`, toutes les réponses 5xx sont des échecs. Un rechargement
Admin/SIGUSR1 compatible conserve l'état ; modifier la politique de protection
ou la liste des upstreams repart d'un état neuf.

Les dépassements d'en-têtes, de body et de durée totale reçoivent une erreur
HTTP explicite tant que le protocole peut encore l'envoyer ; les transports
inactifs et les connexions HTTP/2 ou HTTP/3 en excès sont fermés. Pingora 0.9.0
n'expose qu'un seul timer de lecture amont en H1/H2 : la valeur la plus stricte
entre `first_byte_timeout` et `between_reads_timeout` régit donc les deux
phases. Le bridge H3 change de timer après réception de l'en-tête de réponse.
La modification du `header_timeout` avant routage, de la limite de section H2
ou du nombre de connexions H1/H2 exige actuellement un redémarrage du listener.

Admin `/load`, `pingclair reload`, SIGUSR1 et `run --watch` publient les
changements compatibles dans une seule transaction préparée. Les clés API,
les origines, la désactivation d'Admin, les routes des listeners existants, le
contenu des certificats manuels et un trust pool mTLS existant prennent effet
avant que le succès soit annoncé ; une connexion admise par une ancienne
génération mTLS doit se reconnecter. Un changement qui exige de reconstruire
les sockets ou les contextes TLS — ajout ou suppression d'un listener, ajout
d'un nom TLS, modification d'une politique capturée par le transport, ou
activation de mTLS sur un listener qui autorisait auparavant la reprise de
session — est refusé en
conservant la dernière configuration valide. L'API Admin renvoie `409` avec
`"restart_required": true` et n'enregistre pas automatiquement le document
refusé.

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
        to 10.0.0.1:8080 {
            weight 3
        }
        to 10.0.0.2:8080
        # 🛟 Utilisé seulement quand tous les backends principaux sont indisponibles.
        to 10.0.0.3:8080 {
            backup
        }
        health_check {
            path /health
            interval 5s
            timeout 2s
            status 200 204
            consecutive_failure 3
            consecutive_success 2
            max_response_body_bytes 65536
            slow_start 30s
        }
    }
}
```

Une réponse relayée porte deux en-têtes d'identification, et **ce proxy réécrit
les deux** : le `Server` de l'amont est remplacé par `Pingclair` — il n'est pas
transmis tel quel — et `Via` porte `1.1 Pingclair`. Un `x-request-id` est ajouté
à chaque réponse en plus des requêtes. C'est une différence délibérée avec Caddy,
qui transmet le `Server` de l'amont intact et envoie `Via: 1.1 Caddy` ; elle est
écrite ici parce qu'une règle de supervision fondée sur l'une de ces chaînes
obtient une réponse différente sans que la configuration ait changé. Le sens
« supprimer » est disponible depuis le DSL (`header -Server` retire l'en-tête,
`header Server <value>` pose le vôtre), mais transmettre la valeur exacte de
l'amont n'est pas implémenté : rien n'expose les en-têtes de réponse de l'amont
sous forme de placeholder.

Les vérifications actives s'exécutent hors bande : un backend inactif en panne
quitte la rotation avant de recevoir une requête utilisateur, puis la rejoint
après les succès consécutifs configurés. Les sondes acceptent method, Host,
headers, statuts, comparaison de body bornée, port dédié, réutilisation de
connexion, seuils et slow-start. En HTTPS, elles réutilisent la CA épinglée,
le certificat client, le SNI et la politique de protocole de la route.

### Limitation de débit locale et exacte

```caddyfile
api.example.com {
    @api path /api/*
    route @api {
        rate_limit 100 60s {
            burst 20
            key tenant X-Tenant-ID
        }
        reverse_proxy app:8080
    }
}
```

Le token bucket émet des champs de réponse exacts `RateLimit-Limit`,
`RateLimit-Remaining` et `RateLimit-Reset`, ainsi que `Retry-After` lors d'un
refus. Ajoutez `dry_run` au bloc pour compter et signaler sans renvoyer 429.
La clé peut être `ip`, `global`, `route`, `api_key`, `header <name>` ou
`tenant [name]`. Ce limiteur est local au processus ; la limitation distribuée
avec Redis est hors du périmètre de la v0.2.

Le schéma de l'amont sélectionne le protocole de connexion : une adresse nue ou
`http://` utilise HTTP/1.1, `https://` négocie HTTP/2 avec repli HTTP/1.1 par
ALPN, `h2c://` impose HTTP/2 en clair avec connaissance préalable, et `h2://`
impose HTTP/2 sur TLS. Utilisez `h2c://` ou `h2://` pour gRPC natif afin de
préserver les trailers de réponse comme métadonnées de bout en bout.

Un amont sur socket Unix s'écrit `unix//path/to.sock` et se connecte à cette
socket ; `unix+h2c//path/to.sock` parle HTTP/2 en connaissance préalable par
dessus. Les amonts Unix ne passent jamais par le rafraîchissement DNS.

Les amonts peuvent aussi être découverts par DNS pendant l'exécution :
`dynamic a name port` résout chaque adresse de `name`, et
`dynamic srv _svc._tcp.example.com` résout les enregistrements SRV dont les
cibles portent leur propre port. L'intervalle `refresh` de chaque source est
indépendant ; s'il est omis, il suit le `dns_refresh` global. Sans option
`resolvers`, la configuration DNS du système hôte est utilisée. Pour une source
SRV, `grace_period` conserve le dernier ensemble valide seulement entre le
premier échec et l'expiration de cette fenêtre bornée ; sans cette option, un
échec retire les amonts dynamiques. `dial_fallback_delay` est refusé, car
Hickory n'expose aucun mécanisme RFC 6555 équivalent pour joindre un serveur
DNS explicite ; l'option n'est jamais acceptée comme no-op. Les résolutions sont
planifiées en arrière-plan, jamais sur le chemin de requête. Une adresse de dial peut aussi
contenir des placeholders — `reverse_proxy {re.dial.1}` — développés par
requête et mis en cache par hôte et port.

La politique de nouvelle tentative accepte les orthographes `lb_retry_match` de
Caddy : `method`, `path`, `header` et expressions CEL. Les expressions de
méthode, de chemin et de code de statut sont évaluées à l'exécution ; les
expressions que le runtime ne peut pas évaluer restent dans la configuration
compilée et sont journalisées au démarrage. `lb_policy weighted_round_robin`
porte un poids par amont, et un bloc `method`/`rewrite` de reverse_proxy modifie
la requête amont avant son envoi.

`request_buffers <taille>` et `response_buffers <taille>` lisent le corps de ce
côté en mémoire avant de le transmettre, de sorte qu'un pair lent occupe ce
proxy plutôt qu'un worker du backend. Les tailles suivent la distinction
SI/IEC — `1MB` vaut un million d'octets, `1MiB` vaut 1 048 576 — et `unlimited`
est accepté. **Ici, `unlimited` ne signifie pas mémoire illimitée** : la mise en
tampon s'arrête à un plafond fixe de 8 Mio et le reste du corps continue en
flux, ce qui est signalé au démarrage puis une fois de plus, une seule, quand un
corps dépasse réellement son tampon. Dans les deux cas le corps arrive complet ;
ce qui change, c'est le moment où il commence à circuler. La mise en tampon n'a
aucun effet sur un transport `fastcgi`, ce que le serveur signale aussi au
démarrage.

`reverse_proxy` accepte aussi les blocs `handle_response` avec des matchers de
réponse (`@name status …` / `@name header …`), `replace_status`,
`copy_response` et `copy_response_headers`. La décision se prend à partir de
l'en-tête seul ; un remplacement émet son corps statique une fois puis jette le
corps amont morceau par morceau, donc l'interception ne met jamais en tampon une
réponse entière. `intercept { … }` enregistre les mêmes handlers pour les
réponses proxifiées.

Les middlewares au niveau du site sans matcher, tels que `header`,
`request_header`, `basic_auth` et `request_body`, s'appliquent aussi aux routes
`handle` qui répondent elles-mêmes. Les middlewares de la route s'exécutent
ensuite et peuvent remplacer les valeurs par défaut du site.

`forward_auth <gateway> { uri …; copy_headers … }` effectue un aller-retour
d'authentification avant que la requête continue vers le backend. Un 2xx copie
les en-têtes de réponse listés vers leurs destinations configurées sur la
requête — en supprimant d'abord ces destinations, y compris celles renommées —
et tout autre statut est répondu directement au client.
Les noms d'en-têtes entrants contenant `_` sont supprimés, comme par défaut
chez Caddy. Ce raccourci est compilé en sous-requête proxy GET sans corps,
qui transmet la méthode et l'URI d'origine ; H1, H2 et H3 partagent le même
échange en streaming.
Le bloc accepte aussi `transport http { … }` avec `tls`, `tls_server_name`,
`tls_trusted_ca_certs`, `tls_client_auth` et `tls_insecure_skip_verify`, selon
les mêmes règles TLS amont que `reverse_proxy`. Les autres options de transport
restent non prises en charge dans `forward_auth`.

Les amonts écrits sous forme de noms d'hôtes sont ré-résolus pendant l'exécution :
un conteneur qui redémarre sur une nouvelle adresse est suivi sans rechargement.
Une résolution en échec laisse l'adresse précédente en rotation — une panne du
résolveur ne doit pas faire tomber le site — et un nom qui ne résout pas au
démarrage rejoint le pool dès qu'il le fait, ce qui permet au proxy de démarrer
avant son application. Les adresses IP littérales n'atteignent jamais un résolveur.

```caddyfile
{
    # ⏱️ 30s par défaut. `dns_refresh off` fige les noms ordinaires et les sources
    # ⏱️ dynamiques sans `refresh` propre ; un intervalle explicite reste actif.
    # ⏱️ L'unité est obligatoire : `30` n'est pas `30s`.
    dns_refresh 15s
}
```

### Applications monopages : `try_files`

`try_files` réécrit la requête vers le premier candidat qui existe sous le
`root` du site, et ne sert rien lui-même — c'est le `file_server` qui suit qui
répond. Le motif standard pour une application monopage fonctionne tel quel :

```caddyfile
example.com {
    root * /srv
    encode gzip
    try_files {path} /index.html
    file_server
}
```

Une requête vers un vrai fichier obtient ce fichier ; tout le reste est réécrit
vers `/index.html` pour que l'application fasse son propre routage. La query
string survit à la réécriture.

🚫 `encode` n'accepte pas de matcher ici. La forme documentée par Caddy est
`encode [<matcher>] <formats…>`, et un matcher est refusé avec un message qui
dit pourquoi : la compression est configurée **par serveur**, il n'y a donc nulle
part où noter « gzip, mais seulement sous `/assets` ». Le contournement tient en
une ligne — déplacer ces chemins dans leur propre bloc de site — et le refus le
dit, plutôt que de rapporter le matcher comme un codage inconnu, ce qui
enverrait chercher une faute d'orthographe.

🏷️ L'`ETag` d'un fichier statique dérive de **sa taille et de son mtime en
nanosecondes** — `"<taille hex>-<mtime ns hex>"`, avec `-gzip` et compagnie
ajouté pour une représentation codée — ou d'un fichier sidecar quand le site en
maintient un. Caddy envoie à la place un court hachage du contenu : déplacer un
site de l'un à l'autre change donc le validateur de **tous** les fichiers d'un
coup, et chaque `If-None-Match` qui aurait répondu `304` répond `200` à la
requête suivante. S'aligner sur Caddy impliquerait de lire chaque fichier pour le
hacher, un coût sur le chemin de requête qui n'a pas été mesuré ; le format est
donc écrit ici pour que la migration soit un événement connu plutôt qu'une
surprise de bande passante.

📦 **La compression est opt-in**, comme chez Caddy : un site ne compresse que là
où une directive `encode` le demande, et l'exemple ci-dessus est ce qui l'active.
`encode gzip` — ou `encode zstd gzip`, qui liste les préférences dans l'ordre —
couvre tout le site ; une réponse `text/*` est alors compressée dès que
l'`Accept-Encoding` du client le permet, avec un `Content-Encoding` et un `ETag`
suffixé `-gzip`. Seules les réponses au-dessus d'un seuil de taille sont
compressées. Un site sans `encode` sert les octets tels qu'ils sont sur le
disque, même si le client annonce gzip ; pour désactiver la compression sur un
site qui a des codages, écrivez `encode off`, et pour en exempter un
`file_server` précis, mettez `file_server { compress off }` dedans. Une
configuration JSON garde l'ancien comportement — `encodings` absent vaut gzip —
pour qu'un document stocké écrit avant l'existence de ce champ continue de
répondre exactement comme il a été écrit.

Une réponse proxifiée reste exactement telle que
l'amont l'a envoyée si elle est partielle (`206`, ou tout `Content-Range`),
répond à un `HEAD`, n'a pas de corps (`204`, `304`) ou porte
`Cache-Control: no-transform` ; quand elle est compressée, `Accept-Encoding`
s'ajoute à son `Vary` existant au lieu de le remplacer, et les champs de
condensat de l'origine (`Content-Digest`, `Repr-Digest`, `Digest`,
`Content-MD5`) sont retirés, puisqu'ils ne décrivent plus les octets.
`Accept-Ranges: bytes` est annoncé aussi sur une réponse compressée d'un
`file_server`, et une requête `Range` reste résoluble : la compression à la
volée est ignorée dès qu'un intervalle est servi, donc le `206` renvoyé contient
les octets du fichier identity aux décalages promis par cet en-tête, et non des
décalages dans le flux gzip.

Un candidat terminé par `/` ne correspond qu'à un répertoire, et un candidat
sans `/` qu'à un fichier ordinaire — la barre oblique qui tranche est celle
écrite dans la configuration, pas celle portée par la requête.

`try_files {path} {path}/ /index.html` fonctionne aussi : le second candidat
correspond à un répertoire, si bien qu'une requête vers `/docs` trouve `/docs/`
et que le serveur de fichiers prend le relais.

La directive est un raccourci plutôt qu'un handler à part entière. Elle se
développe en un matcher `file` suivi d'une réécriture vers le candidat que ce
matcher a retenu, d'où vient tout le reste de son comportement :

```caddyfile
example.com {
    root * /srv

    # 🔍 Un glob nomme l'unique bundle haché sur le disque sans connaître son hachage.
    try_files /build/app.*.js

    # 🎲 Une politique de sélection, quand « le premier qui existe » n'est pas la règle.
    try_files {path} {path}.html {
        policy most_recently_modified
    }

    # 🚨 Un candidat qui est un code de statut lève ce statut au lieu de correspondre.
    try_files {path} =404

    file_server
}
```

Les cinq politiques sont `first_exist` (par défaut), `first_exist_fallback`,
`smallest_size`, `largest_size` et `most_recently_modified`. Un candidat peut
nommer n'importe quel placeholder auquel la requête sait répondre — `{path}`,
`{uri}`, `{query}`, `{host}`, `{method}`, `{http.request.header.*}`,
`{http.vars.*}`, `{re.*}` et les autres — et un candidat portant une query
string (`/index.php?{query}`) remplace celle de la requête lorsque c'est lui
qui a correspondu.

Trois choses restent en **échec fermé**, avec un message qui nomme la raison
plutôt qu'une compilation au sens subtilement différent :

| Refusé | Pourquoi |
| --- | --- |
| Un segment `..` dans un candidat | Le confinement est lexical : un candidat pouvant sortir du root est refusé d'emblée plutôt que vérifié à chaque requête. |
| Un placeholder que le matcher ne sait pas résoudre (`{env.HOME}`, `{scheme}`) | Il serait cherché comme un nom de fichier contenant des accolades — une erreur de configuration impossible à distinguer d'un fichier manquant. |
| Une `policy` inconnue, ou toute autre sous-directive | Une politique inconnue ne correspond à rien, ce qui se lit en production comme « aucun de ces fichiers n'existe ». |

🛡️ Les métacaractères de glob arrivant *dans la valeur d'un placeholder* sont
échappés : une requête vers `/*` ne peut pas transformer
`try_files /files/{path}` en listage de répertoire. Seul le texte de la
configuration décide si un candidat est développé comme un glob.

### Chirurgie de chemin : `uri`

```caddyfile
example.com {
    uri strip_prefix /api
    uri strip_suffix .php
    uri path_regexp /{2,} /
    reverse_proxy 127.0.0.1:3000
}
```

`uri replace` et `uri query` sont **refusés nommément**. Dans Caddy, `replace`
substitue une sous-chaîne du chemin, alors que la réécriture de Pingclair
remplace le chemin entier ; l'accepter compilerait et servirait une URL autre
que celle écrite, d'où l'erreur. La réécriture de query string n'existe pas
encore ici.

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

### Ce que `adapt` produit, et ce qu'il ne produit pas

`pingclair adapt -c Pingclairfile` compile la configuration et l'imprime en
JSON. Ce document est **le format propre à Pingclair**, pas celui de Caddy : son
niveau supérieur est `debug`/`servers`/`admin`/`global`/`logging` là où celui de
Caddy est `{"apps":{…}}`, et ses handlers s'écrivent `{"type":"respond"}` là où
ceux de Caddy s'écrivent `{"handler":"static_response"}`. Les deux formats ne
partagent aucune clé de premier niveau ni aucun nom de handler, donc :

- La sortie **est** chargeable par ce serveur — `pingclair validate <fichier.json>`,
  `run --config <fichier.json>` et `POST /load` acceptent tous ce format, et
  `adapt` la valide avant de l'imprimer précisément pour cela.
- La sortie **n'est pas** chargeable par Caddy, et celle de `caddy adapt` ne
  l'est pas ici. Un artefact `caddy adapt` conservé dans un dépôt est
  l'enregistrement de cette configuration Caddy, pas quelque chose que ce
  serveur sait lire ; migrer signifie garder le Caddyfile, que les deux serveurs
  analysent.
- Un Pingclairfile réécrit à la main dans la sortie de `adapt` est portable
  entre installations Pingclair — un conteneur, un dépôt GitOps, une autre
  machine — et c'est pour ce cas que le format JSON existe.

### Snippets et importations

Un snippet est un fragment réutilisable `(name) { … }` inséré avec
`import name`. Une importation peut fournir un bloc au snippet, qui est inséré
à l'endroit où le snippet écrit `{block}` ; les sous-blocs nommés sont
adressés avec `{blocks.<key>}` :

```caddyfile
(site) {
    https://{args[0]} {
        {block}
    }
}

import site test.domain {
    reverse_proxy 127.0.0.1:3000 {
        header_up Host {host}
    }
}
```

Un placeholder sans contenu est remplacé par rien, donc un snippet qui écrit
`{block}` compile même quand l'appel ne fournit pas de bloc. Un placeholder
dans une liste d'arguments est refusé : la couche de tokens de Caddy peut
relire la ligne après l'insertion, l'arbre de directives ne le peut pas, alors
Pingclair le dit au lieu de deviner. Les définitions de snippets importées
depuis un fichier sont visibles par les importations ultérieures.

### Grammaire des journaux

`log <name> { … }` suit Caddy : le bloc configure un **logger nommé par site**
et le nom est son identifiant. `log <name>` sans bloc référence toujours un
canal global déclaré dans les options globales, et un `log` nu active le
sink d'accès par défaut du site. Les blocs `log` acceptent `hostnames`,
`include`/`exclude` (global), `sampling` et les options de rotation de
fichier (`mode`, `dir_mode`, `roll_*`) ; `log_skip` exclut les requêtes
correspondantes du journal d'accès.

🚫 Un bloc `log { … }` global **sans nom** — celui qui configure le logger par
défaut du processus chez Caddy — est refusé. Les diagnostics d'exécution vont sur
stderr et la sortie du logger de processus n'est pas encore configurable :
accepter le bloc compilerait un réglage qui ne produirait jamais le fichier qu'il
nomme. Nommez le bloc pour déclarer un canal qu'un site peut référencer, ou
placez-le dans un bloc de site pour journaliser les requêtes de ce site.

📝 Pour un trafic soutenu, utiliser
`log { output file /var/log/pingclair/access.log }` avec une politique de rotation ;
les diagnostics peuvent rester sur stderr. Les sorties d'accès configurées
regroupent les entrées complètes par lots de 64 KiB au maximum, avec une vidange
prévue après 5 ms, avant rotation ou lors d'une demande explicite de vidange.
Les entrées individuelles plus grandes contournent le tampon. Les champs et les
règles d'échantillonnage par défaut restent inchangés. Une file
bornée compte les entrées perdues si la sortie ne suit plus
(`pingclair_access_log_dropped_total`). L'arrêt normal accorde aux entrées acceptées
un délai total de 250 ms, sans garantie de durabilité. Le journal système ajoute
également son propre coût de traitement pour chaque requête.

### Ce qui n'est pas encore pris en charge

Pingclair se dit compatible Caddyfile ; la moitié honnête de cette affirmation
consiste à dire où elle s'arrête. Les noms des listes ci-dessous sont
**reconnus** : les écrire produit une erreur qui nomme la fonctionnalité plutôt
que le mot, jamais un `Unknown directive`, et une configuration qui les utilise
ne démarre pas.

📌 La promesse porte sur **ces noms, et rien d'autre**. Elle ne dit rien d'une
sous-option ni d'une orthographe *à l'intérieur* d'un bloc, et ce n'est pas une
échappatoire : chacun de ces cas a son propre traitement, énoncé là où il
appartient. Le bloc `tls { … }` liste plus bas les options qu'il refuse ; la
section sur la grammaire des journaux dit quelles formes un bloc `log` accepte ;
un `log { … }` global sans nom y est refusé ; et une directive peut être
acceptée à un niveau et refusée à un autre. Une phrase qui prétendrait davantage
promettrait une propriété de toute la surface de configuration, ce que cette
section existe précisément pour éviter.

Directives :

  `fs` `invoke` `log_append` `log_name` `map`
  `push` `skip_log` `tracing`

Options globales :

  `acme_ca` `acme_ca_root` `acme_eab` `cert_issuer`
  `cert_lifetime` `ech` `events` `fallback_sni`
  `filesystem` `frankenphp` `key_type` `ocsp_interval`
  `on_demand_tls` `preferred_chains` `renew_interval`
  `shutdown_delay` `storage_clean_interval`

Options du bloc `tls` :

  `protocols` `ciphers` `curves` `alpn`
  `load` `ca` `ca_root` `key_type`
  `eab` `issuer` `get_certificate` `on_demand`
  `reuse_private_keys` `insecure_secrets_log` `renewal_window_ratio`
  `force_automate`

Une sous-option de `servers { … }` est refusée **par son nom** plutôt que prise
pour une faute de frappe : `timeouts`. Caddy la charge, donc une configuration
migrée la rencontre ; ce build n'a pas de délais par listener, et le message dit
quelle capacité manque au lieu d'un `Unknown directive`.

`listener_wrappers` accepte une enveloppe et refuse les autres par leur nom.
`proxy_protocol` exige un en-tête PROXY protocol sur chaque listener que la
Caddyfile déclare, ce qui est le sens du bloc `servers` sans adresse en amont ;
les sources dont l'en-tête est accepté sont les plages `trusted_proxies`, comme
pour l'orthographe par listener. **C'est le `fallback_policy require` d'en
amont**, et l'écart avec le nom nu mérite d'être connu avant de migrer : en
amont, `proxy_protocol` seul vaut `fallback_policy ignore` et répond à une
requête sans en-tête (mesuré sur `caddy v2.11.4`), alors qu'ici cette connexion
est refusée. `fallback_policy require` est acceptée parce qu'elle nomme ce
comportement ; les politiques permissives (`ignore`, `use`, `reject`, `skip`)
ainsi que `timeout` et `allow`/`deny` sont refusées par leur nom avec la raison,
jamais ignorées. `tls` et `http_redirect` sont refusées avec la raison : ici le
TLS est choisi par site par le HTTPS automatique et non par une enveloppe de
listener, et la redirection HTTP vers HTTPS appartient au port en clair
compagnon que le HTTPS automatique crée — un listener déclaré avec `listen` ne
redirigerait pas. `servers <address> { listener_wrappers { … } }` est refusé lui
aussi : ce build applique les options d'un bloc `servers` à chaque listener, et
exiger l'en-tête PROXY sur un port dont les clients ne l'envoient pas les rejette
tous.

Des noms se situent entre les listes ci-dessus et la prise en charge complète,
et sont donc nommés ici plutôt que dans l'une ou l'autre. `copy_response` et
`copy_response_headers` sont des sous-directives de `handle_response` et
fonctionnent à cet endroit ; écrites comme directives à part entière, elles sont
refusées — c'est pourquoi elles figuraient dans la liste. `pki` et
`acme_server` s'analysent, se valident et se sérialisent — une configuration
qui les contient se charge et s'exécute — mais Pingclair n'agira pas comme
autorité de certification pour d'autres clients, et le dit au lieu de n'émettre
silencieusement rien. `dns` et `acme_dns` sont implémentés pour Cloudflare ;
tout autre nom de fournisseur est refusé au démarrage plutôt qu'accepté et
ignoré.

Trois conséquences méritent d'être énoncées franchement, car elles décident si
Pingclair convient, plutôt que d'être des détails découverts plus tard :

- **DNS-01 ne livre qu'un seul fournisseur : Cloudflare.**
  Dans un bloc `tls { … }` propre à un site, indiquez à la fois `auto` et
  `dns cloudflare <token>` : `auto` autorise l'émission publique, tandis que
  `dns` choisit la preuve de contrôle. L'option globale `acme_dns` place tous
  les sites automatiques sur DNS-01 et fonctionne sur un hôte dont le port 80
  est injoignable. Un site `*.example.com` demande ce certificat générique et
  sert chaque nom qu'il couvre avec cette seule feuille ; indiquez aussi l'apex
  (`example.com`) s'il doit répondre là, car un certificat générique couvre
  exactement un label. Tout autre nom de fournisseur est refusé nommément au
  démarrage : le serveur ne se rabat pas sur HTTP-01, car HTTP-01 ne peut pas
  prouver le contrôle d'un nom générique et l'échec n'apparaîtrait qu'au
  renouvellement, dans un message qui ne mentionne jamais l'option choisie.
- **PHP passe par `php_fastcgi` via FastCGI** en HTTP/1.1 et HTTP/2 ;
  l'HTTP/3 refuse les routes FastCGI avec un 501 tant que le planificateur H3
  n'a pas son propre client FastCGI.
- **Certificats et état uniquement sur disque local** (`storage`) : plusieurs
  instances ne peuvent pas partager un même magasin de certificats.

`handle_errors` mérite sa propre ligne, et ce paragraphe disait auparavant
l'inverse : il affirmait que le type « existe dans ce dépôt et ne fait rien, il
est donc refusé plutôt qu'accepté ». Il est **accepté, et il s'exécute** — le
bloc traite le statut remonté, et à l'intérieur `{err.status_code}`,
`{err.status_text}` et `{err.message}` portent l'erreur qui est entrée dans le
handler. Les formes longues `{http.error.*}` lisent les mêmes valeurs, parce que
l'adaptateur de Caddy réécrit la forme courte en forme longue. Seuls
`{err.trace}` et `{err.id}` ne sont pas implémentés : rien ici n'enregistre
l'origine de l'erreur ni un identifiant d'occurrence, ils s'étendent donc en
chaîne vide. Une page d'erreur personnalisée peut aussi passer par `error_page`,
une directive de Pingclair et non de Caddy.

> 🔁 Un test échoue dès que l'analyseur refuse un nom que ce fichier ne
> mentionne pas : la liste ne peut donc pas prendre du retard sur la table que
> consulte l'analyseur. Un README qui annonce une prise en charge que le
> binaire n'a pas est pire qu'un README qui en annonce moins.

### Un défaut connu : les upgrades WebSocket échouent sous charge

Pingclair relaie le WebSocket, et environ **10 à 15 % des upgrades échouent
lorsque la machine est chargée**. Ce point figure ici plutôt que dans la liste
ci-dessus parce que la fonctionnalité n'est pas absente : elle fonctionne, puis
par intermittence ne fonctionne plus.

Le défaut se situe dans `pingora-proxy 0.9.0`, et non dans la manière dont ce
projet traite l'upgrade : une trace confirme que la requête parvient à l'amont
en portant `Connection: Upgrade` et `Upgrade: websocket`. Ticket amont :
[cloudflare/pingora#946](https://github.com/cloudflare/pingora/issues/946),
ouvert au 2026-09-10. Le correctif proposé,
[cloudflare/pingora#947](https://github.com/cloudflare/pingora/pull/947), attend
encore une revue du mainteneur.

Ce qui se passe, en une phrase : une requête d'upgrade est un `GET` sans corps,
et la fin de *ce corps vide* est prise pour la fin du tunnel — mais uniquement
lorsque le `101` de l'amont est lu en premier, une course que le proxy perd
d'autant plus souvent que la machine est occupée.

C'est cet ordonnancement qui rend le défaut invisible. Sur une machine à dix
cœurs au repos, le test d'upgrade passe quarante fois sur quarante ; dans un
conteneur à deux cœurs, il échoue six fois sur quarante ; et introduire le
moindre délai avant le `101` de l'amont — même un simple yield — fait
entièrement disparaître les échecs. Une machine de développement vous dira donc
que ce défaut n'existe pas.

Aucune configuration ne permet de l'éviter. Vu de l'extérieur, l'échec se
manifeste par une connexion détruite immédiatement après le `101`, les deux
extrémités voyant un EOF, sans erreur.

## 🏗️ Architecture

Pingclair est organisé en workspace Cargo modulaire :

| Crate (module) | Description |
|----------------|-------------|
| **`pingclair`** | **Point d'entrée CLI.** Analyse les arguments, initialise la journalisation, amorce le système. |
| **`pingclair-core`** | **Cœur d'exécution.** Structures de données, traits et gestion du cycle de vie du serveur. |
| **`pingclair-config`** | **Compilateur de configuration.** Analyse lexicale, syntaxique et sémantique du `Pingclairfile`, puis génération des objets de configuration d'exécution. |
| **`pingclair-proxy`** | **Implémentation du proxy.** Logique de proxy HTTP/TCP bâtie sur le trait Proxy de Pingora, répartiteur de charge inclus, ainsi que l'écouteur HTTP/3 (QUIC) bâti sur quiche de Cloudflare. |
| **`pingclair-static`** | **Service de fichiers statiques.** Lecture de fichiers efficace, déduction du type MIME et transmission en flux. |
| **`pingclair-tls`** | **Gestion TLS.** Certificats manuels, autorité interne persistante et émission automatique via ACME (Let's Encrypt). |
| **`pingclair-api`** | **API d'administration.** Interface RESTful pour consulter l'état ou recharger la configuration à chaud, à l'exécution. |
| **`pingclair-plugin`** | 🚧 **Ébauche, inutilisable.** Squelette d'une future interface de plugins, sans aucun appelant dans l'espace de travail. Une configuration nommant un handler `plugin` est **rejetée**, plutôt qu'acceptée puis silencieusement ignorée. Prévu pour v0.3. |

## 🤝 Contribuer

Les contributions sont les bienvenues — qu'il s'agisse de corriger un bug, d'ajouter une fonctionnalité ou simplement d'améliorer la documentation.

Commencez par lire **[CONTRIBUTING.md](CONTRIBUTING.md)**. Il décrit les quatre commandes que chaque commit doit passer, ce qui constitue une couverture de tests suffisante pour un serveur web, et les contraintes d'architecture que le code seul ne révèle pas (édition de liens BoringSSL, chemin HTTP/3, mémoire bornée).

Ce qui a changé d'une version à l'autre — et ce qui se trouve sur `main` sans être encore publié — est consigné dans **[CHANGELOG.md](CHANGELOG.md)**.

Les nouveaux contributeurs signent un [CLA](CLA.md) une seule fois. **Vous conservez le droit d'auteur sur votre travail.**

## 📄 Licence

Ce projet est distribué sous **licence Apache 2.0**. Voir [LICENSE](LICENSE) pour les termes complets et [NOTICE](NOTICE) pour les obligations d'attribution et les composants tiers.

---

<div align="center">
  <sub>Conçu avec ❤️ et Rust</sub>
</div>
