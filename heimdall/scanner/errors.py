"""Erreurs du scanner déterministe (#53, #22).

Un scan incomplet ne produit jamais un verdict propre : toute erreur de
lecture, de confinement ou de décodage remonte en ``ScanError``. Les messages
sont statiques et ne reflètent jamais une entrée (invariant 8) : ni chemin, ni
extrait de fichier, ni valeur candidate.

``InvalidFinding`` et ``InvalidTarget`` dérivent aussi de ``ValueError`` : un
appelant qui traite les erreurs de contrat comme des valeurs invalides
continue de fonctionner.
"""


class ScanError(Exception):
    """Échec fail-closed du scanner ; le message ne contient aucune entrée."""


class InvalidFinding(ScanError, ValueError):
    """Un Finding ne respecte pas le contrat Finding v1 (#14)."""


class InvalidTarget(ScanError, ValueError):
    """Une cible d'analyse ne respecte pas le contrat (chemin, lignes)."""


class ScanIncomplet(UserWarning):
    """Des contenus ont été laissés de côté : le verdict « propre » n'est pas fondé.

    Ce n'est **pas** une erreur : ``scan()`` reste utilisable pour lister les
    Findings lus. Mais un appelant qui conclut « dépôt propre » à partir d'une
    liste vide doit savoir que des contenus (binaire, lien symbolique, base
    VCS) n'ont pas été lus : le rapport (``RapportScan.complet``) et l'API
    stricte (``scan_complet()``) portent la réponse exacte.
    """
