"""Erreurs du scanner déterministe (#22).

Un scan incomplet ne produit jamais un verdict propre : toute erreur de
lecture, de confinement ou de décodage remonte en ``ScanError``. Les messages
sont statiques et ne reflètent jamais une entrée (invariant 8) : ni chemin, ni
extrait de fichier, ni valeur candidate.
"""


class ScanError(Exception):
    """Échec fail-closed du scanner ; le message ne contient aucune entrée."""
