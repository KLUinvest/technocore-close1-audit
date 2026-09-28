# Technocore close-1 archive auditor

Outil Python **strictement en lecture seule** pour vérifier les archives publiques du challenge Technocore `close-1` et retrouver un trade par identifiant exact.

Il a été créé à partir d’un cas réel de participation : l’offre maker `msea2d166ee04c17` avait été contresignée, mais son résultat n’était pas récupérable avec certitude dans les résumés `d-close1-flow` tronqués. L’archive officielle publiée ensuite permet désormais d’établir son résultat.

## Résultat reproductible

Pour le sweep **646**, l’archive officielle contient à l’index `1063` :

- trade : `msea2d166ee04c17`
- maker : `did:key:z6MkmGZTwZzkTVxKgEmUCWBGmEWyZszcA2qLC9PfF7WucJTy`
- countersigner : `did:key:z6MkhTH7zUkPKnm3Sygr8gdBHi4Ek2nXV2GpG9Wm3bC4CRFN`
- termes : maker `sell`, `qty=5`, `px=225.21`, `until=692`
- résultat officiel index-aligné : `void`
- raison : `funds`

Conséquence : ce trade n’a pas créé la position SHORT 5 attendue pour le maker.

Le rapport machine est versionné dans [`reports/msea2d166ee04c17.json`](reports/msea2d166ee04c17.json).

## Vérifications effectuées

L’outil :

1. télécharge `index.json` depuis l’hôte officiel autorisé ;
2. sélectionne l’entrée du sweep exact ;
3. télécharge uniquement le fichier référencé par l’index ;
4. vérifie son SHA-256 avant de parser le JSON ;
5. exige l’alignement par index entre `input.trades` et `output.trades` ;
6. recherche l’identifiant avec une égalité exacte, jamais par sous-chaîne ;
7. rapporte les occurrences exactes du DID demandé.

Aucune clé, signature, requête POST ou identité privée n’est utilisée.

## Utilisation

Python 3.11+, sans dépendance externe :

```bash
python3 close1_audit.py \
  --sweep 646 \
  --trade-id msea2d166ee04c17 \
  --did did:key:z6MkmGZTwZzkTVxKgEmUCWBGmEWyZszcA2qLC9PfF7WucJTy
```

Pour créer un nouveau rapport sans écraser un fichier existant :

```bash
python3 close1_audit.py \
  --sweep 646 \
  --trade-id msea2d166ee04c17 \
  --did did:key:z6MkmGZTwZzkTVxKgEmUCWBGmEWyZszcA2qLC9PfF7WucJTy \
  --output reports/audit.json
```

Tests :

```bash
python3 -m unittest discover -s tests -v
```

## Modèle d’intégrité et limites

L’archive distingue deux statuts :

- `full` : les octets téléchargés peuvent être comparés directement au hash `file` engagé par le sweep signé ;
- `redacted` : des trades de rooms privées sont remplacés. Le fichier public modifié ne peut donc plus être comparé au hash signé `file`; son intégrité est vérifiée contre le champ `sha256` de l’index public.

Le sweep 646 est **redacted** (`316` entrées). Le rapport vérifie correctement le hash public `0285da2a…f77b9e1`, mais indique explicitement `signed_file_hash_verifiable: false`. L’outil ne présente donc pas ce fichier redacted comme le préimage exact du hash signé original.

Autres limites :

- les signatures Ed25519 des messages de chat ne figurent pas dans la forme normalisée du sweep et ne sont pas revérifiées ici ;
- l’outil vérifie un sweep demandé, pas l’historique complet d’un compte ;
- une entrée privée redacted ne peut pas être reconstituée ;
- la confiance dans un fichier redacted dépend de l’index servi par l’archive officielle.

## Sécurité

- GET HTTPS uniquement vers `challenges.technocore.chat` ;
- refus des redirections hors origine ;
- aucun accès à `identity.pem` ;
- aucune signature ;
- aucune publication Technocore ;
- aucune transaction.

## Sources officielles

- [Archive publique close-1](https://challenges.technocore.chat/close-1/)
- [Index des sweeps](https://challenges.technocore.chat/close-1/index.json)
- [README de l’archive](https://challenges.technocore.chat/close-1/README.txt)
- [Règles et fold close-1](https://github.com/flop-labs/technocore-close-call-challenge)
- [Issue #6 — publication de l’archive](https://github.com/flop-labs/technocore-close-call-challenge/issues/6)

## Licence

MIT — voir [LICENSE](LICENSE).
