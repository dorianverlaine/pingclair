# Site officiel de Pingclair

[English](README.md) · **Français** · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md)

## Présentation

Site officiel : [https://pingclair.com](https://pingclair.com)

Le code source du site officiel de Pingclair est désormais hébergé dans un dépôt distinct :

**[dorianverlaine/pingclair-docs](https://github.com/dorianverlaine/pingclair-docs)**

Depuis cette migration, le présent répertoire ne contient plus les sources du site. L'ancienne arborescence et les fichiers `.gitkeep` qui permettaient de conserver les répertoires vides ont également été supprimés.

Seule la configuration du site en production est conservée ici. Elle constitue un exemple concret de déploiement avec le langage de configuration natif de Pingclair.

Ce `Pingclairfile` illustre la mise en place d'un site de documentation statique et regroupe plusieurs fonctionnalités :

- Gestion automatique des certificats TLS et prise en charge de HTTP/3
- Hébergement de plusieurs sites virtuels sur un même point d'écoute
- Distribution de fichiers statiques et pages d'erreur personnalisées
- Proxy inverse et mise en cache des réponses
- Sélection d'une représentation Markdown pour les agents IA
- Redirections permanentes et gestion du domaine principal
- Journalisation structurée des accès et rotation automatique des journaux

## Configuration en production

Le fichier `Pingclairfile` ci-dessous correspond à la configuration utilisée pour `pingclair.com`.

Le site est hébergé sur un serveur FreeBSD situé à Paris, avec Pingclair comme serveur HTTP. Le sous-domaine `pingclair.pingclair.com` reste disponible pour les essais et la préproduction, tandis que `www.pingclair.com` redirige définitivement vers le domaine principal.

Les commentaires en anglais sont conservés afin de faciliter la comparaison avec le fichier déployé.

```swift
// 🏝️ pingclair.com — the docs site, served by Pingclair from the Paris
// FreeBSD node, with pingclair.pingclair.com kept as the staging alias and
// www redirected to the apex.

AutomaticTLS(mode: .automatic, httpPort: 80, httpsPort: 443)
Storage(root: "/var/db/pingclair")

// 🔁 The Admin API on loopback, so `pingclair reload` can hot-reload this
// file instead of a restart dropping connections.
Admin(listen: "127.0.0.1:2019")

// 🧊 The one-line install address: `https://pingclair.com/install.sh`.
//
// The script lives in the server repository and is published to the release
// bucket by every release; proxying it here rather than keeping a copy is the
// same choice the Cloudflare Worker made — there is no second file to drift.
let installerHost = "releases.pingclair.com:443"

// 🤖 The agent endpoints still served by the documentation Worker; the
// Paris node proxies them so `pingclair.com/mcp` and `/a2a` keep the URL
// contract the Worker era established.
let cfWorker = "cf.pingclair.com:443"

HTTPListener(on: ":443") {
    Site(host: "pingclair.com") {
        Route(when: .path(exact: "/install.sh")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/install")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/mcp")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        Route(when: .path(exact: "/a2a")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        // 📄 Agents that ask for markdown get the twin on the same URL: the
        // directory's `index.md`, or the sibling `<name>.md`; a miss carries
        // on to the normal file server unchanged. The `index.md` copies are
        // made at deploy time.
        Route(when: .header(name: "Accept", contains: "text/markdown")) {
            TryFiles(candidates: [.requestPath(appending: "index.md"), .requestPath(appending: ".md")], root: "/usr/local/www/pingclair.pingclair.com")
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Fallback {
            // 🔗 `public/_headers` states these on the Cloudflare deployment;
            // the native file server does not read that file, so the Paris
            // node states the same rules here.
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", "</.well-known/api-catalog>; rel=\"api-catalog\", </llms.txt>; rel=\"describedby\", </sitemap.xml>; rel=\"sitemap\""))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
    }
    // 🧾 Starlight ships a 404 page; unknown paths answer with it, the same
    // as the Cloudflare deployment's `not_found_handling`.
    .errorPage(for: [.status(404)], file: "/usr/local/www/pingclair.pingclair.com/404.html")
    .encode(.zstd, .gzip)

    Site(host: "www.pingclair.com") {
        // ➡️ 308 to the apex, the same permanent move the Cloudflare zone
        // answered. The native language has no request-time placeholders yet,
        // so the path does not ride along; a `keepPath:` argument on Redirect
        // is the design idea on file for that.
        Fallback { Redirect(to: "https://pingclair.com", status: .permanentRedirect) }
    }

    Site(host: "pingclair.pingclair.com") {
        Route(when: .path(exact: "/install.sh")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/mcp")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        Route(when: .path(exact: "/a2a")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        // 📄 The same markdown negotiation as the apex site.
        Route(when: .header(name: "Accept", contains: "text/markdown")) {
            TryFiles(candidates: [.requestPath(appending: "index.md"), .requestPath(appending: ".md")], root: "/usr/local/www/pingclair.pingclair.com")
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Fallback {
            // 🔗 The same header set as the apex site.
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", "</.well-known/api-catalog>; rel=\"api-catalog\", </llms.txt>; rel=\"describedby\", </sitemap.xml>; rel=\"sitemap\""))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
    }
    .errorPage(for: [.status(404)], file: "/usr/local/www/pingclair.pingclair.com/404.html")
    .encode(.zstd, .gzip)
}
.tls(.automatic(email: "team@pingclair.com"))
// 📓 One JSON line per request, rotated by Pingclair itself.
.accessLog(
    output: .file("/var/log/pingclair-access.log"),
    format: .json,
    headers: [.request("User-Agent")],
    rotation: .roll(size: .mebibytes(100), keep: 7, compress: true),
)
```

## Explication de la configuration

### 1. Paramètres globaux et définition des serveurs en amont

Les directives `AutomaticTLS` et `Storage` définissent respectivement la gestion des certificats TLS et l'emplacement des données persistantes du service.

```swift
AutomaticTLS(mode: .automatic, httpPort: 80, httpsPort: 443)
Storage(root: "/var/db/pingclair")
Admin(listen: "127.0.0.1:2019")
```

`AutomaticTLS` active la gestion automatique des certificats et précise les ports HTTP et HTTPS utilisés notamment pour leur émission et leur renouvellement.

`Storage` définit le répertoire dans lequel Pingclair conserve les certificats TLS, les clés des comptes ACME et les données associées.

`Admin` publie l'API d'administration sur l'adresse de bouclage, ce qui permet d'appliquer une modification de configuration par un rechargement à chaud plutôt que par un redémarrage.

Deux déclarations `let` permettent également de définir les adresses des serveurs en amont :

```swift
let installerHost = "releases.pingclair.com:443"
let cfWorker = "cf.pingclair.com:443"
```

Ces déclarations évitent de répéter les mêmes adresses dans plusieurs règles et garantissent leur cohérence dans l'ensemble de la configuration.

Dans le langage natif de Pingclair, les chaînes de caractères sont toujours interprétées littéralement. L'interpolation de variables dans une chaîne n'est volontairement pas prise en charge.

Les références explicites aux valeurs déclarées avec `let` permettent ainsi de résoudre la configuration dès son chargement et d'en vérifier le contenu sans dépendre d'une substitution effectuée au moment des requêtes.

### 2. Points d'écoute et hôtes virtuels

```swift
HTTPListener(on: ":443") {
    Site(host: "pingclair.com") { ... }
    Site(host: "www.pingclair.com") { ... }
    Site(host: "pingclair.pingclair.com") { ... }
}
```

`HTTPListener` définit un point d'écoute réseau. Chaque bloc `Site` décrit ensuite le comportement à appliquer selon le nom d'hôte demandé.

Plusieurs sites virtuels peuvent donc partager un même point d'écoute, sans qu'il soit nécessaire d'ouvrir une connexion d'écoute distincte pour chacun.

Le déploiement actuel comprend trois hôtes virtuels :

| Nom d'hôte | Fonction |
|---|---|
| `pingclair.com` | Site officiel et principaux points d'entrée de l'API |
| `www.pingclair.com` | Redirection permanente vers le domaine principal |
| `pingclair.pingclair.com` | Environnement de préproduction et point d'accès conservé pour des raisons de compatibilité |

Cette organisation sépare la gestion des connexions réseau des règles propres à chaque site. Les paramètres TLS, la journalisation et les autres fonctionnalités communes restent ainsi centralisés au niveau du point d'écoute.

### 3. Ordre d'évaluation des routes

Pingclair examine les blocs `Route` dans leur ordre de déclaration. Dès qu'une règle correspond à la requête, celle-ci est prise en charge par la route concernée.

Si aucune règle ne correspond, le bloc `Fallback` assure le traitement par défaut.

Pour le site officiel, les règles sont organisées dans l'ordre suivant :

1. Scripts d'installation : `/install.sh` et `/install`
2. Interfaces destinées aux agents : `/mcp` et `/a2a`
3. Sélection du contenu Markdown selon l'en-tête `Accept`
4. Distribution des fichiers statiques par `Fallback`

Les routes correspondant à des chemins précis sont placées avant la règle plus générale fondée sur les en-têtes HTTP. Les interfaces dédiées ne risquent donc pas d'être interceptées par la logique de sélection du format ou de distribution des fichiers.

L'ordre de traitement est directement visible dans le fichier de configuration. Aucun système de priorité numérique ni aucune règle implicite supplémentaire ne sont nécessaires.

### 4. Proxy inverse et mise en cache

Le script d'installation du projet est distribué par un service de publication indépendant. Le site de documentation n'en conserve pas de copie locale.

Les chemins `/install.sh` et `/install` sont associés à un proxy inverse qui transmet les requêtes à `releases.pingclair.com` :

```swift
Rewrite(to: "/pingclair/install.sh")
Proxy(
    to: installerHost,
    headersUp: [.set("Host", "releases.pingclair.com")],
    headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
)
.upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
.cache(ttl: .minutes(5), maxSize: .mebibytes(16))
```

Plusieurs opérations interviennent dans ce traitement :

1. **Réécriture du chemin** : `Rewrite` remplace le chemin demandé par celui utilisé sur le service de publication.
2. **Transmission de la requête** : `Proxy` établit une connexion avec le serveur HTTPS en amont.
3. **Définition de l'en-tête Host** : `headersUp` renseigne explicitement le nom d'hôte à transmettre au serveur distant.
4. **Configuration TLS** : `upstreamTLS` précise le nom de serveur utilisé lors de la connexion TLS en amont.
5. **Mise en cache** : `cache` définit une durée de validité de cinq minutes et une limite de taille de 16 MiB.
6. **Identification de la source** : `headersDown` ajoute l'en-tête `X-Installer-Source: r2` si celui-ci est absent de la réponse.

Le choix explicite des noms d'hôte HTTP et TLS est essentiel dans cette architecture.

Si la requête transmise conservait `pingclair.com` comme en-tête `Host`, Cloudflare pourrait la rediriger vers le serveur du site officiel et provoquer une boucle de proxy.

La configuration distingue donc clairement le domaine public utilisé par les visiteurs du nom d'hôte du service en amont.

La distribution du script par un service dédié évite également de devoir synchroniser plusieurs copies entre le site web et l'infrastructure de publication des versions.

#### Interfaces destinées aux agents

Les chemins `/mcp` et `/a2a` utilisent le même mécanisme de proxy inverse, mais sans mise en cache des réponses.

```swift
Route(when: .path(exact: "/mcp")) {
    Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
    .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
}
```

Ces interfaces restent hébergées sur un Cloudflare Worker. Le serveur du site officiel se charge uniquement de lui transmettre les requêtes.

Cette organisation permet de conserver les adresses publiques existantes, sans imposer de modification aux clients lors du changement d'infrastructure.

### 5. Contenu Markdown pour les agents IA

Le site officiel peut fournir une page au format HTML ou Markdown à une même adresse, selon l'en-tête HTTP `Accept` envoyé par le client.

```swift
Route(when: .header(name: "Accept", contains: "text/markdown")) {
    TryFiles(
        candidates: [
            .requestPath(appending: "index.md"),
            .requestPath(appending: ".md")
        ],
        root: "/usr/local/www/pingclair.pingclair.com"
    )
    ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
}
```

*Cet extrait a été remis en forme pour en faciliter la lecture. Son fonctionnement est identique à celui de la configuration en production.*

Lorsqu'un client transmet un en-tête `Accept` contenant `text/markdown`, Pingclair recherche une version Markdown de la ressource demandée.

`TryFiles` examine successivement deux chemins possibles :

1. Le fichier `index.md` situé dans le répertoire correspondant à l'URL demandée
2. Un fichier `.md` correspondant au chemin demandé

Si un fichier existe, son chemin est retenu pour la suite du traitement. `ServeFiles` se charge alors de le transmettre au client.

Si aucun des fichiers recherchés n'est présent, `TryFiles` ne renvoie pas immédiatement d'erreur. La requête poursuit son traitement avec son chemin initial.

Les ressources statiques ordinaires et les pages dépourvues de version Markdown restent donc accessibles sans modification.

Lors du déploiement, les fichiers `index.md` nécessaires sont également générés à partir des fichiers Markdown correspondants, afin de prendre en charge les URL de documentation se terminant par un répertoire.

Pour les navigateurs classiques, le site continue de fournir les pages HTML. Les fichiers Markdown ne figurent pas dans la liste des fichiers d'index par défaut du serveur et ne remplacent donc pas les pages `index.html`.

**Limite de l'implémentation actuelle :** Pingclair vérifie simplement si l'en-tête `Accept` contient `text/markdown`. Ce mécanisme permet de sélectionner une représentation, mais ne constitue pas une implémentation complète de la négociation de contenu HTTP, notamment en ce qui concerne les préférences et les coefficients de qualité.

L'objectif est de permettre aux agents IA de récupérer directement une version textuelle structurée de la documentation, tout en conservant les mêmes URL et le comportement habituel des navigateurs.

Pour une présentation plus générale des enjeux liés à l'accessibilité des sites pour les agents IA, voir l'article de Cloudflare :

[Agent Readiness](https://blog.cloudflare.com/agent-readiness/)

### 6. Domaine principal et redirections permanentes

Le domaine principal du site est `pingclair.com`. Les requêtes adressées à `www.pingclair.com` font l'objet d'une redirection permanente HTTP 308.

```swift
Site(host: "www.pingclair.com") {
    Fallback {
        Redirect(
            to: "https://pingclair.com",
            status: .permanentRedirect
        )
    }
}
```

Le code HTTP 308 indique que la redirection est permanente et impose au client de conserver la méthode de la requête initiale.

**Une limitation subsiste : le chemin de la requête n'est pas conservé lors de la redirection.**

Par exemple, une requête vers `https://www.pingclair.com/docs/example` est redirigée vers `https://pingclair.com`, et non vers la page correspondante sur le domaine principal.

Cette limitation tient au fait que le langage de configuration natif ne permet pas encore de construire une destination de redirection dynamique à partir du chemin demandé.

Plusieurs solutions sont à l'étude dans le [ticket nº 330](https://github.com/dorianverlaine/pingclair/issues/330), dont l'ajout éventuel d'un paramètre `keepPath` à `Redirect`.

### 7. TLS et HTTP/3

```swift
.tls(.automatic(email: "team@pingclair.com"))
```

La configuration TLS du point d'écoute assure la gestion automatique des certificats, depuis leur émission jusqu'à leur renouvellement.

L'adresse `team@pingclair.com` est utilisée comme adresse de contact du compte ACME associé.

Le déploiement prend également en charge HTTP/3, qui repose sur QUIC et utilise UDP sur le port 443.

HTTP/3 et les connexions HTTPS classiques peuvent utiliser le même numéro de port : les premières reposent sur UDP, tandis que les secondes utilisent TCP.

### 8. Pages d'erreur et compression des réponses

Le site officiel utilise la page `404.html` générée par Starlight pour les ressources introuvables.

```swift
.errorPage(
    for: [.status(404)],
    file: "/usr/local/www/pingclair.pingclair.com/404.html"
)
.encode(.zstd, .gzip)
```

`errorPage` associe le code HTTP 404 au fichier HTML indiqué, afin de présenter une page d'erreur cohérente avec le reste du site.

La directive `encode` active les encodages Zstandard et Gzip. Les réponses peuvent ainsi être compressées en fonction des formats acceptés par le client.

### 9. Journaux d'accès et rotation automatique

```swift
.accessLog(
    output: .file("/var/log/pingclair-access.log"),
    format: .json,
    headers: [.request("User-Agent")],
    rotation: .roll(
        size: .mebibytes(100),
        keep: 7,
        compress: true
    ),
)
```

Les journaux d'accès sont enregistrés au format JSON dans le fichier :

`/var/log/pingclair-access.log`

Chaque requête donne lieu à une entrée JSON distincte, ce qui facilite la collecte, la recherche et l'analyse automatisée des journaux.

L'en-tête `User-Agent` est également enregistré. La rotation des fichiers est assurée directement par Pingclair, selon les paramètres suivants :

- Rotation dès que le fichier atteint 100 MiB
- Conservation de sept fichiers après rotation au maximum
- Compression des fichiers après rotation

Le serveur peut ainsi gérer ses journaux d'accès sans recourir à un outil externe tel que `logrotate`.

## Documentation et références

Pour en savoir plus sur le langage de configuration natif de Pingclair et les fonctionnalités disponibles :

- **[Documentation officielle](https://pingclair.com)** : référence du langage de configuration, présentation des fonctionnalités et guides de déploiement
- **`pingclair describe`** : affiche la liste des composants de configuration reconnus par le parseur ainsi que leurs définitions
- **`pingclair validate`** : vérifie un fichier de configuration et signale les erreurs de syntaxe ou de configuration en indiquant leur emplacement
- **[Dépôt du site officiel](https://github.com/dorianverlaine/pingclair-docs)** : code source du site et documentation associée

Cette configuration présente un cas réel de déploiement de Pingclair en production. Pour connaître les paramètres disponibles et les fonctionnalités prises en charge, il convient de consulter la documentation correspondant à la version utilisée.
