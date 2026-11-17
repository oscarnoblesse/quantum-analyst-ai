# Publier la version v1.0.0 (release, signature, Zenodo)

Procédure à suivre une seule fois, dans l'ordre, au moment de figer la version évaluée.
L'évaluation porte **exclusivement** sur l'archive Zenodo de v1.0.0 : tout ce qui n'y est pas
au moment du tag n'existe pas pour le correcteur. Un DOI est permanent : on ne le « corrige » pas,
on publie une nouvelle version (v1.0.1), qui reçoit un autre DOI.

## 0. Une fois pour toutes, avant le tag

1. **Relier Zenodo à GitHub** : se connecter sur <https://zenodo.org> avec le compte GitHub, ouvrir
   *Account → GitHub*, puis activer l'interrupteur du dépôt `oscarnoblesse/quantum-analyst-ai`.
   Zenodo n'archive que les releases publiées **après** cette activation.
2. **Créer la paire de clés de signature** (minisign, Ed25519), hors du dépôt :

   ```bash
   mkdir -p ~/.minisign
   minisign -G -p cle_publique_minisign.pub -s ~/.minisign/quantum-ready.key
   ```

   - La clé **publique** `cle_publique_minisign.pub` va dans le dépôt (racine).
   - La clé **privée** reste dans `~/.minisign/`, protégée par sa phrase de passe. Elle n'est
     jamais commitée (`.gitignore`, `.dockerignore` et gitleaks la couvrent), ni copiée dans la CI.
     La sauvegarder ailleurs : sans elle, plus de nouvelle version signée par la même clé.
   - Noter l'identifiant de clé (`minisign public key <ID>`, première ligne du fichier public) :
     il va sur la fiche de dépôt (« empreinte de la clé publique de signature »).

## 1. Figer le contenu

1. Tout est fusionné dans `main` : code, documentation, rapport technique, traces, résultats.
2. Les résultats publiés sont à jour (`make metriques` si des mesures ont changé) et relus
   (aucun secret, aucune donnée personnelle dans `traces/`).
3. `uv run python scripts/reproduire.py` réussit sur la machine de l'auteur, et la CI est verte
   sur `main` (y compris les jobs `image-docker` et `integrite`).
4. `CITATION.cff` : ajouter `date-released: AAAA-MM-JJ` (date du tag).

**À partir d'ici, ne plus régénérer aucun résultat** : la signature porterait sur d'autres octets.

## 2. Empreintes et signature

```bash
make sommes                                         # écrit SHA256SUMS (results/, traces/, data/ground_truth/)
make signer CLE_PRIVEE=~/.minisign/quantum-ready.key  # écrit SHA256SUMS.minisig (demande la phrase de passe)
make verifier-signature                             # doit afficher « Signature and comment signature verified »
                                                    # puis « 0 différents, 0 manquants »
git add SHA256SUMS SHA256SUMS.minisig cle_publique_minisign.pub CITATION.cff
git commit -m "v1.0.0 : SHA256SUMS signé"
git push origin main
```

Attendre que la CI soit verte sur ce commit (le job `integrite` vérifie alors la signature).

## 3. Tag et release

```bash
git tag -a v1.0.0 -m "Quantum-Ready v1.0.0"
git push origin v1.0.0
gh release create v1.0.0 --title "Quantum-Ready v1.0.0" --notes-file docs/notes_v1.0.0.md
```

(`docs/notes_v1.0.0.md` : quelques lignes sur le contenu de la version ; ou `--generate-notes`.)
La release est publiée sur GitHub → Zenodo l'archive automatiquement en quelques minutes, avec les
métadonnées de `.zenodo.json`.

## 4. Après l'archivage

1. Sur Zenodo, vérifier la notice : titre, auteur, version **1.0.0**, licence, description.
2. Relever le **DOI de la version** (de la forme `10.5281/zenodo.NNNNNNN`), et non le « concept
   DOI » qui désigne toutes les versions : la fiche exige un DOI correspondant à v1.0.0.
3. Télécharger l'archive `.zip` depuis Zenodo et calculer son empreinte pour la fiche :
   `sha256sum quantum-analyst-ai-v1.0.0.zip` (Windows : `Get-FileHash -Algorithm SHA256 <fichier>`).
4. Refaire la vérification de l'auditeur sur l'archive décompressée (AUDIT.md, section 10).
5. Facultatif, sur `main` après coup : badge DOI dans le README. Il ne sera pas dans l'archive
   v1.0.0 (le DOI n'existe qu'après elle), c'est normal : la fiche porte le lien.

## 5. Fiche de dépôt (Canevas_fiche_de_depot.pdf)

| Champ | Où le trouver |
|---|---|
| Dépôt GitHub | `https://github.com/oscarnoblesse/quantum-analyst-ai` |
| Release v1.0.0 | `https://github.com/oscarnoblesse/quantum-analyst-ai/releases/tag/v1.0.0` |
| DOI Zenodo | DOI de la version (étape 4.2) |
| Intégration continue | page Actions, exécution sur le tag v1.0.0 |
| SHA256SUMS signé | liens vers `SHA256SUMS`, `SHA256SUMS.minisig`, `cle_publique_minisign.pub` au tag v1.0.0 |
| SHA-256 de l'archive Zenodo | étape 4.3 |
| Empreinte de la clé publique | identifiant de clé minisign (étape 0.2) |
