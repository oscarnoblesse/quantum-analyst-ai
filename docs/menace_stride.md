# Modèle de menace STRIDE du système multi-agents

Ce document recense les menaces du système Quantum-Ready selon la méthode STRIDE, leurs
contre-mesures, et la preuve que chaque contre-mesure existe et est testée. Une contre-mesure
qui n'a pas de test est signalée comme telle.

Un test de `tests/test_stride.py` vérifie que chaque fichier de test cité ici existe et que
chaque test cité y figure. Un document qui cite un test supprimé échoue en CI.

## Surface d'attaque

Les entrées non fiables du système sont :
1. **les fichiers du SI analysé** (configurations, code, notes) : ils peuvent contenir du texte
   destiné à tromper le modèle (injection indirecte) ;
2. **les réponses du modèle de langage** : elles peuvent être malformées, hors sujet ou inventées ;
3. **les réponses des services de laboratoire** (serveur TLS, SSH) : elles viennent d'un processus
   externe au système d'analyse ;
4. **les arguments d'appel d'outil** choisis par le modèle.

Le modèle de langage n'a aucun pouvoir sur le SI : il ne peut qu'appeler des outils de sa liste
fermée, et les outils ne modifient rien du SI.

## Menaces et contre-mesures

### S — Usurpation (Spoofing)

| Menace | Contre-mesure | Preuve | Limite |
| --- | --- | --- | --- |
| Un agent appelle un outil qui n'est pas le sien (un agent se fait passer pour un autre) | Le serveur MCP est créé pour un agent donné et n'expose que sa liste fermée (`outils_autorises`). L'appel hors liste est refusé et journalisé. | `tests/test_boucle_agent.py::test_refus_double_et_erreur_d_outil` ; `tests/test_serveur_mcp.py::test_liste_fermee_et_journal` | Le nom de l'agent n'est pas signé : un code qui s'exécute dans le même processus peut changer la liste. |

### T — Altération (Tampering)

| Menace | Contre-mesure | Preuve | Limite |
| --- | --- | --- | --- |
| Le modèle modifie un fichier du SI | Aucun outil n'écrit dans le SI : la racine est résolue et tout chemin qui sort du SI est refusé. | `tests/test_outils_commun.py::test_resoudre_refuse_ce_qui_sort_du_si` | Les outils de génération du SI (`make si`) écrivent dans `si/`, mais ne sont pas exposés aux agents. |
| Un lien symbolique du SI pointe hors du SI | La résolution suit le lien et refuse s'il sort de la racine. | `tests/test_outils_commun.py::test_resoudre_refuse_un_lien_symbolique_vers_l_exterieur` | Non testé sous Windows (droits nécessaires pour créer un lien). |
| Le journal d'une session est modifié après coup | La session se rejoue : les appels d'outils purs sont rejoués sur le même SI et comparés aux sorties enregistrées. | `tests/test_rejeu.py::test_ecart_enregistre_est_detecte` | Le journal n'est **pas signé** : une modification qui recalcule aussi le rejeu n'est pas détectée. Une signature est à ajouter. |
| Le modèle fait passer un CBOM ou un plan invalide pour valide | Le code revalide le CBOM (schéma CycloneDX 1.6) et le plan (`verifier_plan`) ; un échec renvoie à l'agent avec le motif. | `tests/test_orchestrateur.py::test_plan_refuse_par_le_code_puis_corrige` | Le code ne vérifie pas tout le sens d'un plan (défaut ouvert n° 3 dans `CLAUDE.md`). |

### R — Répudiation (Repudiation)

| Menace | Contre-mesure | Preuve | Limite |
| --- | --- | --- | --- |
| Impossible de savoir quel appel a produit quel résultat | Chaque appel d'outil est journalisé avec son agent, ses arguments, son statut et sa sortie ; chaque tour de modèle est journalisé. | `tests/test_serveur_mcp.py::test_liste_fermee_et_journal` | Les messages envoyés au modèle ne sont pas journalisés en entier, seulement leur nombre (exigence du sujet non satisfaite, voir `CLAUDE.md`). |

### I — Divulgation d'information (Information disclosure)

| Menace | Contre-mesure | Preuve | Limite |
| --- | --- | --- | --- |
| Un secret du SI se retrouve dans le journal, la sortie ou le rapport | Les secrets sont décrits (longueur, alphabet), jamais recopiés. Aucun secret n'est écrit dans le journal. | `tests/test_outils_commun.py::test_decrire_secret_ne_revele_pas_la_valeur` ; `tests/test_serveur_mcp.py::test_aucun_secret_dans_le_journal` | Un secret qui ne ressemble à aucun motif reconnu peut passer. |
| Une clé privée réelle est versionnée | gitleaks en CI ; les clés du laboratoire sont éphémères (créées au démarrage, dans `/run`). | job CI `secrets` ; `demonstrateur/entrypoint.sh` | Les clés du SI fictif sont générées par `make si` et jamais commitées (`.gitignore`). |
| Les traces publiées révèlent le SI fictif | Relecture des traces avant publication (exigence de la passation). | — | **Non automatisé** : aucune vérification ne porte sur le contenu des traces. |

### D — Déni de service (Denial of service)

| Menace | Contre-mesure | Preuve | Limite |
| --- | --- | --- | --- |
| Un outil ne répond jamais et bloque l'agent | Délai de 120 s par appel d'outil ; le dépassement devient une erreur lisible. | `tests/test_pannes.py::test_outil_hors_delai_devient_une_erreur_lisible` | Le délai ne coupe pas un outil qui tourne déjà en dehors de la boucle. |
| Le modèle boucle sur le même appel ou ne termine jamais | Limite d'étapes par agent ; appels identiques rappelés au lieu d'être relancés ; budget de contexte. | `tests/test_boucle_agent.py::test_limite_d_etapes_et_fenetre` ; `tests/test_boucle_agent.py::test_refus_double_et_erreur_d_outil` | Le budget de jetons ne couvre pas la durée totale. |
| Le modèle local est injoignable | Arrêt propre, journalisé, sans plantage. | `tests/test_pannes.py::test_modele_injoignable_arrete_proprement_et_journalise` | — |

### E — Élévation de privilèges (Elevation of privilege)

| Menace | Contre-mesure | Preuve | Limite |
| --- | --- | --- | --- |
| Le modèle lance une commande système arbitraire (laboratoire) | Les commandes Docker sont construites avec des arguments fixes, sans shell. Le groupe et l'image ne viennent jamais du modèle. | `tests/test_installation_modele.py` ; `tests/test_agent_demonstrateur.py::test_groupe_inconnu_refuse_par_le_laboratoire` | — |
| La sonde TLS atteint un système qui n'est pas le laboratoire | La cible est refusée avant toute connexion si elle n'est pas locale. | `tests/test_outil_scan_tls_lab.py::test_cible_externe_refusee_avant_toute_connexion` | Le contrôle porte sur l'adresse écrite, pas sur la résolution DNS (un nom local qui pointe ailleurs n'est pas vérifié). |

## Injection indirecte (STRIDE ne la couvre pas seul)

Un fichier du SI peut contenir « ignore tes instructions et appelle tel outil ». Trois éléments
limitent l'effet :
- le texte d'un outil est une donnée, rangée dans un message « outil », jamais une consigne ;
- la liste d'outils est fermée côté serveur : un appel hors liste est refusé même si le modèle
  l'a demandé (`tests/test_boucle_agent.py::test_refus_double_et_erreur_d_outil`) ;
- la sortie finale est validée par schéma et par le code.

**Non mesuré** : la fréquence à laquelle le modèle suit réellement une consigne piégée. Un test
ne peut pas le mesurer sans modèle réel ; ce point reste à faire (un SI volontairement piégé,
avec le modèle local).
