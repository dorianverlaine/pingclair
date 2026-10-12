# Site officiel de Pingclair

[English](README.md) · **Français** · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md)

## Présentation

Site officiel : [https://pingclair.com](https://pingclair.com)

Le code source du site vit dans son propre dépôt,
**[dorianverlaine/pingclair-docs](https://github.com/dorianverlaine/pingclair-docs)**.
Ce répertoire ne conserve que la configuration de production, [`Pingclairfile`](Pingclairfile),
comme exemple concret de déploiement d'un site de documentation statique avec Pingclair :

- certificats TLS automatiques et HTTP/3
- hébergement virtuel par nom pour trois noms d'hôte
- fichiers statiques, page 404 personnalisée et compression
- proxy inverse avec cache de réponses
- Markdown pour les agents IA sur les mêmes URL
- redirection permanente vers le domaine canonique
- journaux d'accès JSON avec rotation intégrée

Le site tourne sur un serveur FreeBSD. `pingclair.pingclair.com` est conservé comme
nom d'hôte de préproduction, et `www.pingclair.com` redirige de façon permanente
vers le domaine principal. Le fichier est un Pingclairfile — la syntaxe du
Caddyfile — et les extraits ci-dessous en sont tirés.

## La configuration, section par section

### 1. Options globales

```caddyfile
{
    email team@pingclair.com
    storage file_system /var/db/pingclair
    admin 127.0.0.1:2019
}
```

`email` est le contact du compte ACME pour les certificats automatiques. `storage`
désigne le répertoire qui conserve les certificats, les clés de compte et l'état
associé. `admin` publie l'API d'administration sur l'interface de bouclage
uniquement, ce qui permet à `pingclair reload` d'appliquer un fichier modifié
sans couper les connexions.

### 2. Des snippets pour ce qui se répète

Les éléments répétés sont définis une seule fois, sous forme de snippets, puis importés :

| Snippet | Contenu |
| --- | --- |
| `(edge_headers)` | Les en-têtes de sécurité et l'en-tête `Link` de découverte pour agents que le déploiement Cloudflare déclarait dans son fichier `_headers` |
| `(installer)` | Le proxy qui sert `install.sh` depuis le stockage des publications |
| `(worker)` | Le proxy des points d'accès pour agents `/mcp` et `/a2a` |
| `(access_log)` | Le journal d'accès commun à tous les sites |
| `(docs)` | Tout le site de documentation, partagé par le domaine principal et l'hôte de préproduction |

### 3. Hôtes virtuels

```caddyfile
pingclair.com {
    import docs
}

pingclair.pingclair.com {
    import docs
}

www.pingclair.com {
    import access_log
    redir https://pingclair.com{uri} 308
}
```

Une adresse de site avec un nom d'hôte obtient automatiquement HTTPS sur le port
443, HTTP/3 sur UDP 443, et une écoute sur le port 80 qui redirige vers HTTPS et
répond aux défis ACME.

| Nom d'hôte | Rôle |
| --- | --- |
| `pingclair.com` | Le site et ses points d'accès pour agents |
| `pingclair.pingclair.com` | Préproduction, qui sert le même site |
| `www.pingclair.com` | Redirection permanente vers le domaine principal |

### 4. Ordre des routes

```caddyfile
route {
    handle /install.sh {
        import installer
    }
    …
    handle {
        import edge_headers
        file_server
    }
}
```

Dans `route`, les blocs s'exécutent dans l'ordre où ils sont écrits, et le
premier `handle` qui correspond répond à la requête. Le site suit cet ordre :

1. le script d'installation, `/install.sh` et `/install` ;
2. les points d'accès pour agents, `/mcp` et `/a2a` ;
3. les règles de bordure pour les ressources de build, l'index de recherche,
   les fichiers Markdown et les documents de découverte `/.well-known` ;
4. le Markdown pour les clients qui le demandent ;
5. tout le reste, servi depuis le disque.

### 5. Proxy du script d'installation, avec cache

```caddyfile
(installer) {
    rewrite * /pingclair/install.sh
    reverse_proxy releases.pingclair.com:443 {
        header_up Host releases.pingclair.com
        header_down ?X-Installer-Source r2
        transport http {
            tls
            tls_server_name releases.pingclair.com
        }
        cache {
            ttl 5m
            max_size 16777216
        }
    }
}
```

Le site ne garde aucune copie du script d'installation : chaque publication le
dépose dans le stockage des publications, et le site sert de proxy vers lui. Le
chemin est réécrit vers celui du stockage, l'en-tête `Host` et le nom de serveur
TLS amont sont fixés explicitement, les réponses sont mises en cache cinq
minutes dans 16 Mio au plus, et `X-Installer-Source: r2` est ajouté si l'amont
ne l'a pas défini.

L'en-tête `Host` explicite compte ici : une requête amont qui garderait
`pingclair.com` pourrait être renvoyée par Cloudflare vers ce même serveur, en boucle.

Les points d'accès `/mcp` et `/a2a` sont toujours servis par un Cloudflare
Worker ; le snippet `(worker)` les relaie de la même façon, sans cache, si bien
que leurs URL n'ont pas changé lors du déménagement du site.

### 6. Règles de bordure

```caddyfile
handle /_astro/* {
    import edge_headers
    header Cache-Control "public, max-age=31536000, immutable"
    file_server
}
```

Le déploiement Cloudflare les appliquait en bordure ; ici, chacune est un bloc
`handle` : cache immuable pour les ressources de build, cache d'une heure pour
l'index de recherche, `text/plain` pour les accès directs aux fichiers Markdown,
accès inter-origines aux documents `/.well-known`, avec le type de média RFC 9727
pour le catalogue d'API.

### 7. Du Markdown pour les agents IA

```caddyfile
@markdown header Accept *text/markdown*
handle @markdown {
    try_files {path}index.md {path}.md
    file_server
}
```

Un client dont l'en-tête `Accept` contient `text/markdown` reçoit la version
Markdown de la page à la même URL : le `index.md` du répertoire, ou le fichier
voisin `<nom>.md`. Si aucun n'existe, la requête continue avec son chemin
d'origine, de sorte que les ressources et les pages sans version Markdown restent
servies. Les navigateurs continuent de recevoir du HTML. Les copies `index.md`
sont générées au déploiement.

Il s'agit d'un test d'en-tête, pas d'une négociation de contenu HTTP complète.
Pingclair propose aussi `file_server { negotiate markdown }`, qui suit les valeurs
de qualité de la RFC 9110 et pose `Vary: Accept` ; le site pourrait l'adopter.

Pour le contexte, voir l'article de Cloudflare [Agent Readiness](https://blog.cloudflare.com/agent-readiness/).

### 8. Page 404 et compression

```caddyfile
encode zstd gzip

handle_errors 404 {
    rewrite * /404.html
    file_server
}
```

`encode` propose Zstandard et gzip aux clients qui les acceptent. Une requête
pour un fichier absent reçoit le `404.html` généré par Starlight, avec le statut
404 conservé.

### 9. Journaux d'accès

```caddyfile
(access_log) {
    log {
        output file /var/log/pingclair-access.log {
            roll_size 100MiB
            roll_keep 7
        }
        format json
        headers {
            request User-Agent
        }
    }
}
```

Chaque requête est une ligne JSON dans `/var/log/pingclair-access.log`, avec le
`User-Agent` de la requête. Pingclair assure lui-même la rotation : à 100 Mio,
en gardant sept fichiers, compressés.

## Références

- **[Documentation officielle](https://pingclair.com)** — référence de
  configuration et guides de déploiement.
- **`pingclair validate`** — vérifie une configuration et indique l'emplacement
  des erreurs.
- **`pingclair fmt`** — met en forme un Pingclairfile en conservant ses commentaires.
- **[Source du site](https://github.com/dorianverlaine/pingclair-docs)** — le
  dépôt du site lui-même.
