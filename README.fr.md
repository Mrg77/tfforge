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

## Ce qu'il fait

- **Une boucle agentique from-scratch** — `message + outils → tool_use → garde →
  exécute → résultat → boucle`, bornée. Écrite en HTTP brut sur l'API Anthropic
  Messages, sans framework — les ~100 lignes qui font le déclic. Le client du
  modèle est une interface, donc toute la boucle est testée avec un faux client
  (sans clé API, sans tokens).
- **Il construit de l'infra.** `write_file` laisse l'agent générer et réécrire
  des fichiers `.tf` (confinés au projet). La sécurité par défaut est dans le
  system prompt : S3 privé + public-access block + chiffrement, IAM least-privilege
  (jamais `Action "*"`), chiffrement au repos, aucun secret en clair.
- **Il sécurise — et modernise — ce qu'il construit.** `security_scan` utilise le
  meilleur scanner installé (**checkov** en priorité, puis trivy, puis tfsec) plus
  une **passe déterministe provider-aware** qui signale en trois catégories :
  - **security** — IAM wildcard, S3 public (ACL **ou** une bucket policy
    `Principal "*"`), chiffrement absent (S3, RDS/Aurora, Redshift, EBS, EFS),
    SSH/RDP ouvert au monde (IPv4 **et** IPv6 `::/0`), ingress/egress grand ouvert,
    `iam:PassRole` sur `*`, secrets en clair (attribut, JSON, **ou** heredoc/
    user_data — sans afficher la valeur). Les règles sont **testées
    adversarialement** : une batterie de cas piégeux verrouille ce qui doit être
    détecté ET ce qui doit rester silencieux (ex. `s3:*` dans un `Deny` est OK, un
    `aws_s3_bucket_acl` moderne n'est pas une déprécation) — donc pas de faux
    positifs qui saoulent ;
  - **version** — syntaxe dépréciée (inline S3 `acl`/`versioning`/chiffrement sur le
    provider moderne), provider AWS périmé (v3 ou moins), `required_version` absent
    ou pré-1.0 — l'agent modernise le code, pas seulement le sécurise ;
  - **best-practice** — région du provider hard-codée, `required_providers` absent,
    fichier multi-ressources sans backend distant.

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
| `ANTHROPIC_API_KEY` | requise pour l'agent — la clé API (facturée au token). Pas nécessaire pour `scan`. |
| `TFFORGE_MODEL` | change le modèle (défaut `claude-sonnet-4-5` ; `claude-haiku-4-5` ~3× moins cher) |
| `TFFORGE_MAX_COST` | arrête le run avant de dépasser ce budget USD (ex. `0.50`) |
| `TFFORGE_AUDIT` | `off` pour désactiver le journal, ou un chemin pour le rediriger |
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

---

Fait partie d'un portfolio DevOps, aux côtés d'
[opsforge](https://github.com/Mrg77/opsforge) (un poste de travail DevOps
policy-as-code) et [KubeForge](https://github.com/Mrg77/kubeforge) (une app
locale d'analyse Kubernetes). MIT · © Mrg77.
