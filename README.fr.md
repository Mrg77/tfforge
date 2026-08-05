# tfforge

*Read this in [English](README.md).*

**Un agent IA qui construit, valide et sécurise du Terraform — avec une couche de garde qu'il ne peut pas contourner.**

tfforge écrit le code Terraform lui-même, le valide, le scanne pour la sécurité,
et **s'auto-corrige jusqu'à ce que ce soit propre** — pendant que chaque action
destructrice passe par des **guards policy-as-code**, pour que l'agent aide sans
pouvoir casser la production. Il est écrit **from scratch sur l'API Anthropic
Messages** (sans framework), donc la boucle agentique est entièrement visible.

> Pas un « LLM qui écrit du HCL » de plus. Le marché en est saturé. La valeur ici,
> c'est la couche de **sécurité, fiabilité et auditabilité** autour d'un agent —
> précisément ce sur quoi les équipes galèrent pour mettre un agent en production.

## Pourquoi ce projet

L'agentic AI en production est avant tout un problème d'**infrastructure et
d'orchestration** : un agent qui appelle des outils, gère les erreurs, respecte
des garde-fous, journalise chaque action, et dont on peut voir le coût. C'est du
DevOps. tfforge en est une démonstration from-scratch, sur une tâche qu'un DevOps
connaît intimement — Terraform — avec les enjeux de sécurité et de LLMOps qui
rendent un agent digne de confiance.

## Comment ça marche

```
  toi : « construis un bucket S3 privé et chiffré avec un IAM least-privilege,
         scanne-le, et corrige ce que tu trouves »
        │
   1. GÉNÈRE ──────▶ l'agent écrit le Terraform lui-même (write_file)
        │
   2. VALIDE ──────▶ terraform_validate (on ne scanne pas du code qui ne parse pas)
        │
   3. SÉCURISE ────▶ security_scan : checkov / trivy / tfsec + checks
        │             provider-aware (IAM wildcard, S3 public, chiffrement absent…)
        │
   4. AUTO-CORRIGE ▶ des findings ? l'agent corrige (edit_file) et re-scanne
        │             (la boucle qui le rend vivant) — jusqu'à ce que ce soit propre
        │
   5. PLANIFIE ────▶ terraform_plan, rendu en tableau lisible
        │
   6. GARDE ───────▶ apply/destroy passent par la policy — destroy sur prod BLOQUÉ
```

## Quel outil pour quoi (soyons honnêtes)

tfforge a deux moitiés très différentes. Utilise la bonne — elles n'ont pas le même coût :

| Tu veux… | Utilise | Coût |
|---|---|---|
| **Écrire / générer du HCL** | ton assistant d'IDE (Claude Code, etc.) — il a le contexte du repo et est déjà payé | ton abonnement |
| **Scanner la sécu d'un dossier** | `tfforge scan <dir>` | **0 token** (déterministe, sans clé API) |
| **Auditer un repo existant entier** | `tfforge audit <repo>` | 0 (seul `--explain` appelle l'API) |
| **Gater une CI** | `tfforge scan --fail-on high` | **0 token** |
| **Appliquer avec un filet** | `tofu apply` derrière la garde tfforge | 0 |

**Le positionnement honnête :** l'*agent* intégré (`tfforge "<tâche>"`, qui appelle l'API
Anthropic au token) est une **démonstration from-scratch** d'une boucle agentique gardée —
c'est la pièce d'entretien (« je sais construire un agent à outils avec une garde qu'il ne
peut pas contourner »), pas la façon la moins chère d'écrire du code au quotidien. La
**valeur durable, c'est la couche déterministe** — `scan`, `audit`, la garde — que ton
assistant d'IDE ne te donne *pas* et qui ne coûte rien. Génère avec le meilleur assistant
que tu as ; sécurise et gate avec tfforge.

> Note sur la version Terraform : le locking S3-natif (`use_lockfile`) exige Terraform
> **≥ 1.10** ou **OpenTofu ≥ 1.10**. Sur un `terraform` plus ancien, l'agent retombe sur une
> table DynamoDB (aujourd'hui déconseillée) juste pour que `validate` passe — donc préfère
> `tofu`.

## Ce qu'il fait

- **Il adopte un repo que tu as déjà.** `tfforge audit <repo>` parcourt un dépôt
  Terraform *existant* en entier — chaque module, chaque environnement — lance
  l'analyse déterministe par dossier, et affiche un **rapport de santé priorisé** :
  les trucs urgents d'abord, sur **cinq catégories** (sécurité, version/dépréciation,
  best-practice, **structure**, **variables**), avec un récap par dossier de *où se
  concentre la dette*. Pas une démo sur fichier vide — c'est le cas du quotidien
  (tu hérites d'un repo et tu demandes « par où je commence ? »). **Zéro token**
  (pas de LLM), donc ça gate aussi la CI, et ça génère un **rapport HTML autonome
  et partageable** — un livrable **à onglets** (un onglet par catégorie, chacun
  compté) que tu ouvres dans un navigateur ou joins à une revue :
  ```sh
  tfforge audit ./infra                                   # rapport texte priorisé
  tfforge audit ./infra --html --out sante.html           # un livrable à onglets, partageable
  tfforge audit ./infra --json --fail-on high             # gate la CI (exit ≠ 0)
  tfforge audit ./infra --html --explain --out sante.html   # + correctifs écrits par l'IA (option, clé requise)
  ```
  Le rapport est **multi-cloud** : il détecte automatiquement les providers en jeu
  (OpenStack/OVH, AWS, GCP, Azure, Cloudflare, Datadog, Kubernetes…) et les affiche
  en chips dans l'en-tête. `--explain` est la couche IA *optionnelle* : avec une clé,
  elle ajoute par finding un correctif en prose **plus un diff avant/après HCL** — le
  code actuel problématique et la version corrigée côte à côte, adaptés au cloud réel
  du repo (un backend Swift/OVH sur un repo OpenStack, pas un S3 AWS). Le « avant »
  est **ton vrai code** et le « après » le correctif qui lui est appliqué — un diff
  fidèle, pas un exemple générique. Le pied du rapport HTML affiche le **coût de
  l'appel IA** (modèle + tokens + ~$) pour la visibilité FinOps. Confidentialité :
  `--explain` envoie à l'API le `.tf` concerné **avec les valeurs de secrets
  masquées** (`password = "***"`) — et **rien n'est envoyé sans `--explain`** (le
  scan est 100 % local). Sans clé, elle **dégrade proprement** et écrit quand même
  le rapport. Le déterministe détecte, l'IA explique.
- **Une boucle agentique from-scratch** — `message + outils → tool_use → garde →
  exécute → résultat → boucle`, bornée. Écrite en HTTP brut sur l'API Anthropic
  Messages, sans framework — les ~100 lignes qui font le déclic. Le client du
  modèle est une interface, donc toute la boucle est testée avec un faux client
  (sans clé API, sans tokens).
- **Il construit de l'infra.** `write_file` laisse l'agent générer et réécrire
  des fichiers `.tf` (confinés au projet). La sécurité par défaut est dans le
  system prompt : S3 privé + public-access block + chiffrement, IAM least-privilege
  (jamais `Action "*"`), chiffrement au repos, aucun secret en clair.
- **Marche avec n'importe quel provider.** L'agent, la garde, `plan` et les
  scanners externes (checkov/trivy) sont **agnostiques** — utilise tfforge sur AWS,
  GCP, Azure ou un cloud privé (VMware, OpenStack…) de la même façon. En plus, les
  règles **maison** de tfforge couvrent les **trois hyperscalers** (AWS, GCP,
  Azure) ; le reste passe par checkov + l'agent + la garde.
- **Il sécurise — et modernise — ce qu'il construit.** `security_scan` utilise le
  meilleur scanner installé (**checkov** en priorité, puis trivy, puis tfsec) plus
  une **passe déterministe provider-aware** qui signale en cinq catégories
  (`audit` les remonte toutes les cinq ; la boucle de build se concentre sur les
  trois premières) :
  - **security** — IAM wildcard, S3 public (ACL **ou** une bucket policy
    `Principal "*"`), chiffrement absent (S3, RDS/Aurora, Redshift, EBS, EFS),
    SSH/RDP ouvert au monde (IPv4 **et** IPv6 `::/0`), ingress/egress grand ouvert,
    `iam:PassRole` sur `*`, secrets en clair (attribut, JSON, **ou** heredoc/
    user_data — sans afficher la valeur). Les règles sont **testées
    adversarialement** : une batterie de cas piégeux verrouille ce qui doit être
    détecté ET ce qui doit rester silencieux (ex. `s3:*` dans un `Deny` est OK, un
    `aws_s3_bucket_acl` moderne n'est pas une déprécation) — donc pas de faux
    positifs qui saoulent. La même rigueur couvre **GCP** (bucket GCS public,
    firewall ouvert au monde, rôles IAM primitifs, clés SA long-terme) et **Azure**
    (règles NSG ouvertes, blob public, HTTPS désactivé, vieux TLS) ;
  - **version** — syntaxe dépréciée (inline S3 `acl`/`versioning`/chiffrement sur le
    provider moderne), provider AWS périmé (v3 ou moins), `required_version` absent
    ou pré-1.0 — l'agent modernise le code, pas seulement le sécurise. En plus des
    règles maison, `security_scan` lance **tflint** s'il est installé, dont les
    règles sont **maintenues par l'écosystème HashiCorp** — donc tfforge continue de
    signaler les *nouvelles* déprécations à mesure que Terraform évolue, sans que
    j'écrive de nouveau code ;
  - **best-practice** — région **ou location** du provider hard-codée (provider-
    agnostique : attrape AWS `us-east-1`, OVH `GRA7`, GCP `us-central1`, Azure
    `westeurope` de la même façon, pas juste AWS), `required_providers` absent, un
    module racine sans backend distant ;
  - **structure** — le même type de ressource copié-collé ≥4× sans
    `count`/`for_each` (une répétition qui appelle un `for_each` ou un module
    extrait pour rester DRY — ex. 14 blocs `datadog_monitor` quasi identiques) ;
  - **variables** — des variables déclarées sans `type` (une mauvaise valeur
    devrait échouer tôt, au plan) ou sans `description` (des inputs
    auto-documentés).

  L'agent scanne, corrige (chirurgicalement avec `edit_file`, pas une réécriture),
  et **re-scanne jusqu'à ce que ce soit propre**.
- **La garde — le différenciateur.** Le même concept policy-as-code que les
  guards d'[opsforge](https://github.com/Mrg77/opsforge), appliqué aux actions de
  l'agent : des règles (`action × contexte → allow/warn/confirm/deny`, first
  match wins). La politique par défaut **refuse `destroy` sur la prod et confirme
  `apply` sur la prod** — et elle **échoue en mode fermé** : un destroy sur un
  contexte qu'elle ne peut pas *prouver* non-prod (elle lit le workspace Terraform
  passivement, pas juste le chemin) est bloqué. Les actions en lecture seule la
  contournent ; les politiques YAML custom sont supportées.
- **Des plans lisibles pour les gros repos.** `terraform_plan` parse
  `terraform show -json` en tableau coloré — compteurs `+create / ~update /
  -destroy / ±replace`, **changements destructeurs en premier**, warning ⚠,
  plafonné avec un rollup par type pour la longue traîne. L'agent ne reçoit qu'un
  **digest compact**, donc un plan de 500 changements n'explose ni le contexte ni
  la facture de tokens. *Le déterministe compte ; l'IA n'explique* — le pattern
  qui scale.
- **Audit + coût + budget (la couche LLMOps).** Chaque tour et chaque action
  gardée sont écrits dans un **journal d'audit** JSONL
  (`~/.local/state/tfforge/audit.jsonl`) — une trace revue de ce que l'agent a
  fait *et de ce que la garde a bloqué*. Les tokens sont valorisés en **coût**
  estimé, affiché dans un résumé de run. Un **budget** (`TFFORGE_MAX_COST`)
  arrête le run avant qu'il ne dépasse un plafond — du FinOps pour agents. L'agent
  est aussi optimisé pour consommer moins : il édite chirurgicalement au lieu de
  réécrire, ne planifie qu'une fois, reste concis ; et `TFFORGE_MODEL=claude-haiku-4-5`
  le fait tourner ~3× moins cher.
- **Un mode CI — sans LLM.** `tfforge scan <dir> [--json] [--fail-on <sev>]`
  lance l'analyse de sécurité déterministe *seule* (sans clé API, sans tokens) et
  **sort en code non-zéro** quand des findings atteignent le seuil — donc le même
  cerveau sécu que l'agent peut gater un pipeline. `--json` sort un rapport
  machine ; les règles provider-aware attrapent des écarts de least-privilege et
  réseau qu'un scanner grossier laisse passer (un wildcard de service `s3:*`, un
  ARN S3 account-wide, du SSH ouvert à `0.0.0.0/0`, `iam:PassRole` sur `*`, une
  base publiquement accessible).

## Installer

```sh
# macOS (Homebrew) :
brew install mrg77/tap/tfforge

# Linux (Debian/Ubuntu/Alpine…) ou macOS — le script d'installation :
curl -fsSL https://raw.githubusercontent.com/Mrg77/tfforge/master/install.sh | sh

# ou depuis les sources :
go build -o tfforge .
```

Le script choisit le bon binaire pour votre OS/arch et le pose dans `~/.local/bin`
(surchargez avec `TFFORGE_INSTALL_DIR`, épinglez avec `TFFORGE_VERSION=v0.1.0`).

## Le lancer

```sh
# 1. Une clé API Anthropic — facturée au token, distincte d'un abonnement Claude.
export ANTHROPIC_API_KEY=...        # https://console.anthropic.com

# 2. Build (ou le brew install ci-dessus)
go build -o tfforge .

# 3. Construire + scanner + auto-corriger un stack S3 sécurisé (la démo phare)
./tfforge "build a private, encrypted S3 bucket with least-privilege IAM in \
  ./examples/out, scan it for security issues, and fix anything the scan finds"

# 4. Voir la garde bloquer un destroy de production
./tfforge "destroy the infrastructure in ./examples/prod"     # → BLOQUÉ par la policy

# 5. Voir le scan + auto-correction réparer du code volontairement cassé
./tfforge "scan ./examples/insecure and fix every security finding, \
  telling me what was wrong and what you changed"

# 6. Mode CI — sans LLM, sans clé. Sort non-zéro sur findings → gate un pipeline.
./tfforge scan ./examples/insecure --json --fail-on high

# 7. Adopter un repo EXISTANT — rapport de santé priorisé (sans LLM), puis un
#    livrable HTML partageable que tu ouvres ou joins.
./tfforge audit ./examples
./tfforge audit ./examples --html --out sante.html
```

Chaque run affiche un résumé : `run summary · N turns · … tokens · M tool call(s)
(K denied) · ~$cost`. Scanners optionnels : `opsforge install checkov` (ou trivy).

## Tests

Pas besoin de clé API ni de réseau — le client du modèle est simulé, la logique
terraform/policy/plan est exercée directement :

```sh
go test ./...
```

Couverture : la boucle agentique (cas nominal, **le guard-deny bloque l'outil**,
bornage de boucle, outil inconnu), la garde (**deny destroy prod**, fail-closed
sur contexte inconnu, warn gardé, fallback policy vide), l'analyseur provider-aware,
le parser de plan (replace dans les deux ordres, truncation gros plan), et
coût/audit.

## Notes de conception

- **Sans framework, volontairement.** Toute la valeur est de voir la boucle.
  `internal/agent` est le petit cœur qui démystifie le fonctionnement d'un agent
  (comme Claude Code).
- **Le Danger est porté par l'outil.** Chaque outil déclare lecture seule /
  mutant / destructeur, donc la garde filtre par vrai rayon d'impact, pas en
  re-devinant l'intention.
- **La garde échoue en mode fermé.** Quand elle ne peut pas prouver qu'une action
  est sûre, elle refuse — l'inverse de faire confiance à un nom de chemin
  contenant « prod ».
- **Limites assumées.** Les checks provider-aware complètent (ne remplacent pas)
  checkov/trivy ; le coût est une estimation ; la garde est un filet solide, pas
  une barrière absolue — à combiner avec des credentials cloud à privilèges
  minimaux (défense en profondeur).

## Configuration

| Variable | Effet |
|---|---|
| `ANTHROPIC_API_KEY` | requise pour l'agent — la clé API (facturée au token). Pas nécessaire pour `scan` ni `audit` (seul `audit --explain` l'utilise). |
| `TFFORGE_MODEL` | change le modèle (défaut `claude-sonnet-4-5` ; `claude-haiku-4-5` ~3× moins cher) |
| `TFFORGE_MAX_COST` | arrête le run avant de dépasser ce budget USD (ex. `0.50`) |
| `TFFORGE_AUDIT` | `off` pour désactiver le journal, ou un chemin pour le rediriger |
| `TFFORGE_TF_BINARY` | force le CLI utilisé (`tofu` / `terraform` / un chemin). Défaut : **tofu s'il est présent**, sinon terraform |
| `NO_COLOR` | désactive la couleur du plan |

### Mode CI (`scan`)

```
tfforge scan <dir> [--json] [--fail-on info|low|medium|high|critical|none]
```

Déterministe, sans LLM, sans clé API. Sort `1` quand le pire finding est au seuil
`--fail-on` ou au-dessus (défaut `high`) ; `--fail-on none` = report-only.
Exemple de gate GitHub Actions :

```yaml
- run: go build -o tfforge . && ./tfforge scan ./infra --fail-on high
```

### Auditer un repo existant (`audit`)

```
tfforge audit <repo> [--json] [--html] [--out FICHIER] [--explain] [--top N] [--fail-on <sev>]
```

Parcourt tout le repo, analyse chaque dossier (module / environnement), et produit
un rapport de santé **priorisé** — pire d'abord, sur cinq catégories (sécurité,
version, best-practice, structure, variables), avec un récap par dossier et les
providers détectés. Déterministe, sans LLM, sans clé. Modes :

| Flag | Sortie |
|---|---|
| *(aucun)* | rapport texte coloré sur stdout |
| `--json` | lisible par machine, pour la CI (la liste complète des findings, non plafonnée) |
| `--html [--out f]` | un rapport HTML **autonome à onglets** — un onglet par catégorie avec compteurs, chips providers, thème clair/sombre, aucune ressource externe, zéro JS. Passe l'échelle des gros repos (plafonne ~50 findings par onglet avec une bannière honnête « top N sur M — lance `--json` pour la liste complète ») |
| `--explain` | couche IA *optionnelle* — par finding, un correctif en prose **plus un vrai diff avant/après HCL** (ton code réel → le fix), adapté au cloud du repo. Envoie le `.tf` concerné à l'API **secrets masqués** ; rien n'est envoyé sans `--explain`. Le pied de page affiche le coût en tokens. Clé requise ; dégrade proprement sans clé |
| `--top N` | combien de findings afficher dans le rapport texte (défaut 10) |
| `--fail-on <sev>` | sort `1` au seuil de sévérité (défaut `none` — report-only) |

> `--explain` coûte des tokens (un seul appel API groupé pour tout le rapport) ;
> tous les autres modes sont gratuits.

```yaml
# Ne casser le build que sur High+ à l'échelle du repo :
- run: go build -o tfforge . && ./tfforge audit ./infra --fail-on high
```

---

Fait partie d'un portfolio DevOps, aux côtés d'
[opsforge](https://github.com/Mrg77/opsforge) (un poste de travail DevOps
policy-as-code) et [KubeForge](https://github.com/Mrg77/kubeforge) (une app
locale d'analyse Kubernetes). MIT · © Mrg77.
