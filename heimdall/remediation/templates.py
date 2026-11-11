"""Templates de remplacement par langage — T30.1 (#83).

Le module répond à une seule question, **sans toucher au disque** : pour un
finding ``(fichier, ligne)`` et un secret connus, quelle expression de lecture
d'environnement faut-il écrire à la place du littéral ?

- Python : ``os.environ["NOM"]`` (échec bruyant si la variable manque) ;
- JavaScript : ``process.env.NOM``.

Le langage est déduit de l'extension du fichier. Le remplacement ne porte que
sur le **littéral de chaîne** contenant exactement le secret, jamais sur la
ligne entière. En cas de doute (f-string, template literal, concaténation,
littéral partiel, plusieurs candidats, ``os`` ou ``process`` masqué, clé
``os.environ``/``process.env`` déjà assainie, directive prologue…), rien n'est
modifié : le résultat est marqué ``manual_remediation=True``. Refuser est
toujours préférable à corrompre le code.

Défenses de ce module :

- aucune exécution du code analysé : ``ast.parse`` et ``tokenize`` lisent, ils
  n'évaluent pas ; la valeur d'un littéral vient de l'AST, jamais d'un
  ``eval`` ou d'un ``exec`` ;
- aucune I/O, aucun appel réseau, aucune dépendance externe ;
- entrées bornées (source 1 Mio UTF-8, secret 100 000 caractères et 1 Mio
  d'octets, nom de variable 64 caractères) : pas d'épuisement mémoire piloté
  par un dépôt hostile ;
- toute erreur d'API est statique (aucun contenu, chemin ou secret reflété) ;
- un patch n'est rendu que si le texte final **reparse** (Python) et si le
  contexte lexical ne révèle aucune ambiguïté.

Portée : le nom de variable est validé ici pour la seule grammaire qui empêche
l'injection de code. La denylist sémantique (``PATH``, ``LD_PRELOAD``…) et le
dédoublonnage appartiennent à #84 ; l'écriture atomique à #85 ; la garde de
chemin runtime à #86.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from typing import Final

from heimdall.scanner.finding import Finding, validate_relative_path

#: Même plafond que le scanner : un fichier scanné ne peut pas être plus gros.
MAX_SOURCE_BYTES: Final[int] = 1_048_576
#: Le nom de variable reste la grammaire fermée du contrat MCP (#16).
MAX_VARIABLE_CHARS: Final[int] = 64
#: Même borne que la revue (#32) pour une valeur connue.
MAX_SECRET_CHARS: Final[int] = 100_000
#: Budget de jetons JavaScript : un fichier de 1 Mio rempli de ``;`` ne doit
#: pas matérialiser un million d'objets avant le refus manuel.
MAX_JS_TOKENS: Final[int] = 100_000
#: Longueur maximale d'un chemin, alignée sur le contrat Finding v1.
MAX_PATH_CHARS: Final[int] = 4096

_VARIABLE: Final[re.Pattern[str]] = re.compile(r"[A-Z][A-Z0-9_]{1,63}")

#: Message unique : une erreur d'API ne reflète jamais son entrée.
_ERROR: Final[str] = "remplacement impossible : entrée invalide"


class Language(str, Enum):
    """Langages pris en charge par les templates de ce sous-ticket."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"


#: Extensions Python acceptées. ``.pyi`` est volontairement absent : un stub
#: ne contient pas de secret exécutable, et le remplacer changerait le typage.
PYTHON_EXTENSIONS: Final[frozenset[str]] = frozenset({".py", ".pyw"})
#: Extensions JavaScript acceptées. JSX et TypeScript sont hors #83 : leurs
#: grammaires (attributs JSX, types) ne sont pas des chaînes JS ordinaires.
JAVASCRIPT_EXTENSIONS: Final[frozenset[str]] = frozenset({".js", ".mjs", ".cjs"})
#: Table unique extension → langage, en minuscules.
EXTENSION_LANGUAGE: Final[dict[str, Language]] = {
    **{extension: Language.PYTHON for extension in PYTHON_EXTENSIONS},
    **{extension: Language.JAVASCRIPT for extension in JAVASCRIPT_EXTENSIONS},
}

#: Templates exposés pour la revue et les tests. Le nom est inséré seulement
#: après validation de sa grammaire fermée.
TEMPLATES: Final[dict[Language, str]] = {
    Language.PYTHON: 'os.environ["{variable}"]',
    Language.JAVASCRIPT: "process.env.{variable}",
}


class TemplateError(Exception):
    """Erreur d'API statique : aucune entrée n'est reflétée."""

    def __init__(self, message: str = _ERROR) -> None:
        super().__init__(message)


class ManualReason(str, Enum):
    """Pourquoi le moteur refuse de produire un patch (remédiation manuelle).

    Ce n'est **pas** une erreur : un cas ambigu est un succès de l'outil qui
    reconnaît ne pas savoir remplacer sans risque.
    """

    UNSUPPORTED_LANGUAGE = "unsupported_language"
    INVALID_SYNTAX = "invalid_syntax"
    STALE_LINE = "stale_line"
    SECRET_NOT_FOUND = "secret_not_found"  # noqa: S105 # nosec B105 - raison, pas un secret
    NO_SIMPLE_LITERAL = "no_simple_literal"
    MULTIPLE_LITERALS = "multiple_literals"
    AMBIGUOUS_STRING = "ambiguous_string"
    AMBIGUOUS_CONCATENATION = "ambiguous_concatenation"
    AMBIGUOUS_CONTEXT = "ambiguous_context"
    SHADOWED_MODULE = "shadowed_module"


@dataclass(frozen=True, slots=True)
class ReplacementPlan:
    """Résultat en mémoire ; ``before``/``after`` ne sortent jamais en repr.

    ``before`` contient le secret par définition, ``after`` ne le contient
    plus. Les deux sont exclus de ``repr`` pour qu'un journal ou une traceback
    ne réécrivent jamais la valeur (invariant 8). Un plan manuel a
    ``after == before``, aucune expression et une raison stable.
    """

    file: str
    line: int
    language: Language | None
    variable: str
    before: str = field(repr=False)
    after: str = field(repr=False)
    expression: str | None
    manual_remediation: bool
    reason: ManualReason | None
    import_added: bool = False
    line_after: int = 0

    def __post_init__(self) -> None:
        try:
            validate_relative_path(self.file)
        except ValueError:
            raise TemplateError from None
        if (
            type(self.line) is not int
            or self.line < 1
            or not isinstance(self.before, str)
            or not isinstance(self.after, str)
            or not isinstance(self.variable, str)
            or _VARIABLE.fullmatch(self.variable) is None
            or (self.language is not None and not isinstance(self.language, Language))
            or not isinstance(self.manual_remediation, bool)
            or not isinstance(self.import_added, bool)
            or type(self.line_after) is not int
            or self.line_after < 1
        ):
            raise TemplateError
        if self.manual_remediation:
            if (
                self.after != self.before
                or self.expression is not None
                or self.reason is None
                or not isinstance(self.reason, ManualReason)
                or self.import_added
            ):
                raise TemplateError
            return
        if (
            self.after == self.before
            or self.reason is not None
            or self.language is None
            or self.expression != replacement_expression(self.language, self.variable)
        ):
            raise TemplateError

    def __repr__(self) -> str:
        """Résumé sans contenu : jamais le secret ni le code environnant."""
        state = "manual" if self.manual_remediation else "patch"
        return (
            f"ReplacementPlan(file={self.file!r}, line={self.line}, "
            f"language={None if self.language is None else self.language.value!r}, "
            f"{state})"
        )


def _check_text(value: object, *, name: str) -> str:
    """Type et borne d'un texte d'entrée, sans jamais refléter sa valeur."""
    if not isinstance(value, str):
        raise TemplateError
    if name == "file":
        if not 1 <= len(value) <= MAX_PATH_CHARS:
            raise TemplateError
        try:
            return validate_relative_path(value)
        except ValueError:
            raise TemplateError from None
    if name == "source":
        if len(value) > MAX_SOURCE_BYTES:
            raise TemplateError
        try:
            if len(value.encode("utf-8", "surrogatepass")) > MAX_SOURCE_BYTES:
                raise TemplateError
        except (UnicodeEncodeError, MemoryError):
            raise TemplateError from None
        return value
    if name == "secret":
        if not 1 <= len(value) <= MAX_SECRET_CHARS:
            raise TemplateError
        try:
            if len(value.encode("utf-8", "surrogatepass")) > MAX_SOURCE_BYTES:
                raise TemplateError
        except (UnicodeEncodeError, MemoryError):
            raise TemplateError from None
        return value
    raise TemplateError


def _check_line(value: object) -> int:
    if type(value) is not int or value < 1:
        raise TemplateError
    return value


def _check_variable(value: object) -> str:
    if not isinstance(value, str) or _VARIABLE.fullmatch(value) is None:
        raise TemplateError
    return value


def detect_language(file: object) -> Language | None:
    """Déduit le langage de l'extension ; ``None`` = remédiation manuelle.

    Un chemin hors contrat Finding lève : l'appelant ne doit pas pouvoir
    confondre « extension inconnue » et « chemin non sûr ».
    """
    path = _check_text(file, name="file")
    suffix = PurePosixPath(path).suffix.lower()
    return EXTENSION_LANGUAGE.get(suffix)


def replacement_expression(language: Language, variable: str) -> str:
    """Rend l'expression exacte du template, après validation du nom."""
    if not isinstance(language, Language):
        raise TemplateError
    name = _check_variable(variable)
    return TEMPLATES[language].replace("{variable}", name)


def _manual(  # noqa: PLR0913 - champs explicites du plan, tous nommés
    *,
    file: str,
    source: str,
    line: int,
    variable: str,
    language: Language | None,
    reason: ManualReason,
) -> ReplacementPlan:
    return ReplacementPlan(
        file=file,
        line=line,
        language=language,
        variable=variable,
        before=source,
        after=source,
        expression=None,
        manual_remediation=True,
        reason=reason,
        import_added=False,
        line_after=line,
    )


def build_replacement(
    file: str,
    source: str,
    line: int,
    secret: str,
    variable: str,
) -> ReplacementPlan:
    """Construit le remplacement d'un littéral de chaîne, ou refuse.

    Le secret doit être la valeur **exacte** du littéral visé. Un secret qui
    n'est qu'une sous-chaîne du littéral (par exemple l'en-tête d'une PEM)
    n'est pas remplacé : le moteur ne devine pas quelles autres données du
    littéral doivent survivre.
    """
    path = _check_text(file, name="file")
    text = _check_text(source, name="source")
    line_number = _check_line(line)
    value = _check_text(secret, name="secret")
    name = _check_variable(variable)
    language = detect_language(path)
    if language is None:
        return _manual(
            file=path,
            source=text,
            line=line_number,
            variable=name,
            language=None,
            reason=ManualReason.UNSUPPORTED_LANGUAGE,
        )
    if language is Language.PYTHON:
        return _python_replacement(path, text, line_number, value, name)
    return _javascript_replacement(path, text, line_number, value, name)


def plan_for_finding(finding: Finding, source: str, secret: str, variable: str) -> ReplacementPlan:
    """Raccourci pour un Finding du contrat #14 (fichier + ligne)."""
    if not isinstance(finding, Finding):
        raise TemplateError
    return build_replacement(finding.file, source, finding.line, secret, variable)


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

_PYTHON_IDENT_EXTRA: Final[frozenset[str]] = frozenset({"_"})
_SIMPLE_STRING_TOKENS: Final[frozenset[int]] = frozenset(
    {
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENDMARKER,
    }
)


def _python_failure(
    file: str, source: str, line: int, variable: str, reason: ManualReason
) -> ReplacementPlan:
    return _manual(
        file=file,
        source=source,
        line=line,
        variable=variable,
        language=Language.PYTHON,
        reason=reason,
    )


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def _annotation_context(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Vrai si le nœud est sous une annotation (chaîne de forward-ref)."""
    child = node
    parent = parents.get(child)
    while parent is not None:
        if (
            (isinstance(parent, ast.AnnAssign) and parent.annotation is child)
            or (isinstance(parent, ast.arg) and parent.annotation is child)
            or (
                isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                and parent.returns is child
            )
        ):
            return True
        child = parent
        parent = parents.get(child)
    return False


def _ambiguous_parent(  # noqa: PLR0911 - un refus explicite par contexte
    node: ast.Constant, parent: ast.AST | None
) -> ManualReason | None:
    """Classe le contexte immédiat : f-string, concaténation ou contexte figé."""
    if parent is None:
        return ManualReason.AMBIGUOUS_CONTEXT
    if isinstance(parent, (ast.JoinedStr, ast.FormattedValue)):
        return ManualReason.AMBIGUOUS_STRING
    template_str = getattr(ast, "TemplateStr", None)
    if isinstance(template_str, type) and isinstance(parent, template_str):
        return ManualReason.AMBIGUOUS_STRING
    interpolation = getattr(ast, "Interpolation", None)
    if isinstance(interpolation, type) and isinstance(parent, interpolation):
        return ManualReason.AMBIGUOUS_STRING
    if isinstance(parent, ast.BinOp):
        return ManualReason.AMBIGUOUS_CONCATENATION
    if isinstance(parent, (ast.Expr, ast.MatchValue, ast.MatchMapping)):
        return ManualReason.AMBIGUOUS_CONTEXT
    if isinstance(parent, ast.Constant):  # pragma: no cover - arbre impossible
        return ManualReason.AMBIGUOUS_CONTEXT
    return None


def _is_os_environ(node: ast.AST) -> bool:
    """Vrai pour l'expression ``os.environ``."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "environ"
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    )


def _is_os_module(node: ast.AST) -> bool:
    """Vrai pour ``os`` ou ``os.environ`` : l'objet qui porte les clés."""
    if isinstance(node, ast.Name):
        return node.id == "os"
    return _is_os_environ(node)


def _python_dynamic_import(node: ast.AST) -> bool:
    """Vrai pour un appel d'import dynamique potentiellement lié à ``os``.

    ``__import__("os")``, ``importlib.import_module("os")`` : ces formes
    contournent la simple résolution du nom ``os`` et doivent être traitées
    comme des racines d'accès à l'environnement.
    """
    function = node.func if isinstance(node, ast.Call) else node
    return (isinstance(function, ast.Name) and function.id in {"__import__", "import_module"}) or (
        isinstance(function, ast.Attribute) and function.attr == "import_module"
    )


def _python_env_access_in(node: ast.AST) -> bool:
    """Vrai si l'expression mentionne une lecture d'``os.environ`` (racine ``os``).

    Couvre les formes directes (``os.environ``, ``os.environ.get``, ``os.getenv``,
    ``operator.getitem``) et les formes indirectionnées : curryfication
    (``getattr(os.environ, "get")("NOM")``), sous-référence via ``vars`` ou
    ``getattr`` (``vars(os.environ)["NOM"]``, ``getattr(os, "environ")["NOM"]``),
    et import dynamique (``__import__("os")``, ``importlib.import_module("os")``).
    Dans chaque cas, la clé littérale deviendrait la valeur lue si le patch était
    appliqué : le contexte est donc un re-ciblage.
    """
    if _is_os_environ(node):
        return True
    if isinstance(node, ast.Attribute):
        return _python_env_access_in(node.value)
    if isinstance(node, ast.Call):
        if _python_dynamic_import(node) or _python_env_access_in(node.func):
            # ``__import__("os")`` / ``importlib.import_module("os")`` : import
            # dynamique, forme d'accès indirect à un module potentiellement ``os``
            # — le doute profite au refus, jamais au remplacement.
            return True
        return any(
            _python_env_access_in(argument)
            for argument in (*node.args, *(keyword.value for keyword in node.keywords))
        )
    if isinstance(node, ast.Subscript):
        return _python_env_access_in(node.value) or _python_env_access_in(node.slice)
    return _is_os_module(node)


def _python_call_env_access(call: ast.Call) -> bool:
    """Vrai pour un appel dont le but ou un argument lit via ``os.environ``."""
    if _python_env_access_in(call.func):
        return True
    if _python_dynamic_import(call):
        # ``__import__("os")``, ``importlib.import_module("os")`` : accès
        # indirect à un module potentiellement ``os`` — le doute profite au refus.
        return True
    return any(
        _python_env_access_in(argument)
        for argument in (*call.args, *(keyword.value for keyword in call.keywords))
    )


def _environment_key_context(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Vrai si le littéral sert de **nom** de variable d'environnement.

    Remplacer ``os.environ["APP_KEY"]`` par ``os.environ[os.environ["APP_KEY"]]``
    changerait la clé lue : le patch est refusé plutôt que corrompu. Le cas
    ``os.getenv(...)``/``os.environ.get(...)`` est traité de la même façon, ainsi
    que les formes indirectionnées (curryfication ``getattr(os.environ, "get")``,
    sous-référence ``vars(os.environ)``/``getattr(os, "environ")``) et les
    imports dynamiques (``__import__("os")``, ``importlib.import_module``).
    """
    child = node
    parent = parents.get(child)
    while parent is not None:
        if isinstance(parent, ast.Subscript) and _python_env_access_in(parent.value):
            # ``os.environ["NOM"]``, ``vars(os.environ)["NOM"]``,
            # ``getattr(os, "environ")["NOM"]`` : la clé devient la valeur.
            return True
        if isinstance(parent, ast.Subscript) and isinstance(parent.value, ast.Call):
            receiver = parent.value.func
            receiver_name = ""
            if isinstance(receiver, ast.Name):
                receiver_name = receiver.id
            elif isinstance(receiver, ast.Attribute):
                receiver_name = receiver.attr
            if receiver_name in _NAMESPACE_READER_FUNCS:
                # ``vars()["NOM"]``, ``locals()["NOM"]``, ``globals()["NOM"]`` :
                # le littéral nomme une entrée de l'espace de noms lui-même ;
                # le patch lirait la valeur d'environnement à la place.
                return True
        if isinstance(parent, ast.Call) and _python_call_env_access(parent):
            # ``os.environ.get("NOM")``, ``getattr(os.environ, "get")("NOM")``,
            # ``operator.getitem(os.environ, "NOM")``, ``getattr(os, "NOM")`` :
            # la clé devient la valeur.
            return True
        child = parent
        parent = parents.get(child)
    return False


#: Appels dont le but évalue le littéral comme du code source (``eval("NOM")``).
_CODE_EVALUATION_FUNCS: Final[frozenset[str]] = frozenset({"eval", "exec", "compile", "__import__"})

#: Récepteurs dont l'espace de noms propre est lu (``vars()["NOM"]``).
_NAMESPACE_READER_FUNCS: Final[frozenset[str]] = frozenset({"vars", "locals", "globals", "dir"})


def _call_resolves_to_eval(call: ast.Call) -> bool:
    """Vrai si l'appel résout (même indirectement) une fonction d'évaluation.

    Couvre les formes directes (``eval``, ``builtins.eval``) et curryfiées
    (``getattr(__builtins__, "eval")``, ``vars()["eval"]`` appelé) : quand le
    but de l'appel est lui-même un appel à ``getattr``/``vars`` dont un
    argument constant nomme une fonction d'évaluation, le littéral passé à
    l'appel externe serait ré-évalué comme du code. Le doute profite au refus.
    """
    function = call.func
    if isinstance(function, ast.Name) and function.id in _CODE_EVALUATION_FUNCS:
        return True
    if isinstance(function, ast.Attribute) and function.attr in _CODE_EVALUATION_FUNCS:
        return True
    if isinstance(function, ast.Call):
        inner = function.func
        inner_name = ""
        if isinstance(inner, ast.Name):
            inner_name = inner.id
        elif isinstance(inner, ast.Attribute):
            inner_name = inner.attr
        if inner_name in {"getattr", "vars"}:
            for argument in (*function.args, *(keyword.value for keyword in function.keywords)):
                if isinstance(argument, ast.Constant) and argument.value in _CODE_EVALUATION_FUNCS:
                    return True
        return _call_resolves_to_eval(function)
    return False


def _python_code_evaluation_context(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Vrai si un ancêtre d'appel évalue le littéral comme du code source.

    ``eval("APP_KEY")`` transformerait la valeur d'environnement en code : le
    patch ``eval(os.environ["APP_KEY"])`` changerait la sémantique (et introduirait
    une évaluation dynamique). Les formes curryfiées
    (``getattr(__builtins__, "eval")("APP_KEY")``) sont refusées de la même
    façon : le doute profite au refus.
    """
    child = node
    parent = parents.get(child)
    while parent is not None:
        if isinstance(parent, ast.Call) and _call_resolves_to_eval(parent):
            return True
        child = parent
        parent = parents.get(child)
    return False


def _single_string_token(segment: str) -> bool:
    """Vrai si le segment AST est exactement **un** jeton de chaîne simple.

    C'est la barrière anti-concaténation : ``"a" "b"`` produit deux jetons
    ``STRING``, même si ``ast`` a replié les deux constantes en une seule.
    """
    try:
        tokens = [
            token
            for token in tokenize.generate_tokens(io.StringIO(segment).readline)
            if token.type not in _SIMPLE_STRING_TOKENS
        ]
    except (tokenize.TokenError, IndentationError, SyntaxError, UnicodeError):
        return False
    if len(tokens) != 1:
        return False
    token = tokens[0]
    return (
        token.type == tokenize.STRING and token.start == (1, 0) and token.end == (1, len(segment))
    )


def _utf8_column_to_char(line: str, column: int) -> int | None:
    """Convertit une colonne AST (octets UTF-8) en indice de caractères."""
    if column < 0:
        return None
    try:
        encoded = line.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if column > len(encoded):
        return None
    try:
        return len(encoded[:column].decode("utf-8"))
    except UnicodeDecodeError:
        return None


def _python_os_status(tree: ast.AST, target_line: int) -> tuple[bool, bool]:  # noqa: PLR0912, PLR0915
    """Rend ``(import_os_avant_la_cible, nom_os_masque_ailleurs)``.

    Un ``import os`` situé après la ligne cible ne rend pas ``os`` disponible
    au moment de l'exécution : il ne compte pas et un import de tête est ajouté.
    """
    module_import = False
    shadowed = False
    top_level = set(tree.body) if isinstance(tree, ast.Module) else set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                binds_os = alias.asname == "os" or (
                    alias.asname is None and (alias.name == "os" or alias.name.startswith("os."))
                )
                if not binds_os:
                    continue
                safe = alias.name == "os" or (alias.asname is None and alias.name.startswith("os."))
                if safe:
                    if node in top_level and node.lineno < target_line:
                        module_import = True
                else:
                    shadowed = True
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.asname == "os" or (alias.asname is None and alias.name == "os"):
                    shadowed = True
        elif isinstance(node, ast.Name):
            if node.id == "os" and isinstance(node.ctx, (ast.Store, ast.Del)):
                shadowed = True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == "os":
                shadowed = True
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arguments = (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                )
                if any(argument.arg == "os" for argument in arguments):
                    shadowed = True
                if node.args.vararg is not None and node.args.vararg.arg == "os":
                    shadowed = True
                if node.args.kwarg is not None and node.args.kwarg.arg == "os":
                    shadowed = True
        elif isinstance(node, ast.Lambda):
            arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            if any(argument.arg == "os" for argument in arguments):
                shadowed = True
            if node.args.vararg is not None and node.args.vararg.arg == "os":
                shadowed = True
            if node.args.kwarg is not None and node.args.kwarg.arg == "os":
                shadowed = True
        elif isinstance(node, ast.ExceptHandler):
            if node.name == "os":
                shadowed = True
        elif isinstance(node, ast.MatchAs):
            if node.name == "os":
                shadowed = True
        elif isinstance(node, ast.MatchStar):
            if node.name == "os":
                shadowed = True
        elif isinstance(node, ast.MatchMapping):
            if node.rest == "os":
                shadowed = True
        type_alias = getattr(ast, "TypeAlias", None)
        if isinstance(type_alias, type) and isinstance(node, type_alias):
            alias_name = getattr(node, "name", None)
            if isinstance(alias_name, ast.Name) and alias_name.id == "os":
                shadowed = True
    return module_import, shadowed


def _python_import_insertion(tree: ast.Module, lines: list[str]) -> int:
    """Index d'insertion de ``import os``, après docstring et futurs imports."""
    body = tree.body
    if not body:  # pragma: no cover - un patch implique du code
        return max(0, len(lines) - 1)
    index = 0
    first = body[0]
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        index = 1
    while index < len(body):
        statement = body[index]
        if not isinstance(statement, ast.ImportFrom) or statement.module != "__future__":
            break
        index += 1
    if index:
        end_line = body[index - 1].end_lineno
        if not isinstance(end_line, int) or end_line < 1:  # pragma: no cover - AST garanti
            return 0
        return end_line
    # La première instruction peut porter des décorateurs : ``FunctionDef.lineno``
    # pointe sur ``def``, donc insérer à ``lineno - 1`` couperait le décorateur.
    first_line = body[0].lineno
    decorators = getattr(body[0], "decorator_list", ())
    for decorator in decorators:
        decorator_line = getattr(decorator, "lineno", first_line)
        if isinstance(decorator_line, int):
            first_line = min(first_line, decorator_line)
    return max(0, first_line - 1)


def _with_python_import(source: str, line: int) -> tuple[str, int] | None:
    """Ajoute ``import os`` au bon endroit ; ``None`` si l'opération échoue."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError, UnicodeError, MemoryError, RecursionError):
        return None
    index = _python_import_insertion(tree, source.split("\n"))
    # ``split("\n")`` conserve le ``\r`` des lignes CRLF : la ligne insérée
    # doit le porter aussi, sinon le fichier devient hétérogène.
    carriage_return = "\r" if "\r\n" in source else ""
    lines = source.split("\n")
    lines.insert(index, "import os" + carriage_return)
    patched = "\n".join(lines)
    try:
        ast.parse(patched)
    except (SyntaxError, ValueError, TypeError, UnicodeError, MemoryError, RecursionError):
        return None
    return patched, line + (1 if index <= line - 1 else 0)


def _python_replacement(  # noqa: PLR0911, PLR0912, PLR0915 - un refus par garde
    file: str, source: str, line: int, secret: str, variable: str
) -> ReplacementPlan:
    lines = source.split("\n")
    if line > len(lines):
        return _python_failure(file, source, line, variable, ManualReason.STALE_LINE)
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError, UnicodeError, MemoryError, RecursionError):
        return _python_failure(file, source, line, variable, ManualReason.INVALID_SYNTAX)
    if not isinstance(tree, ast.Module):  # pragma: no cover - ast.parse rend Module
        return _python_failure(file, source, line, variable, ManualReason.INVALID_SYNTAX)

    parents = _parents(tree)
    matching: list[ast.Constant] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and type(node.value) is str
            and node.value == secret
            and node.lineno == line
        ):
            matching.append(node)

    if not matching:
        reason = (
            ManualReason.NO_SIMPLE_LITERAL
            if secret in lines[line - 1]
            else ManualReason.SECRET_NOT_FOUND
        )
        return _python_failure(file, source, line, variable, reason)
    if len(matching) != 1:
        # Refus avant toute tokenisation de segment : une ligne hostile peut
        # contenir des milliers de littéraux identiques, et ``get_source_segment``
        # recalculerait les lignes à chaque appel.
        return _python_failure(file, source, line, variable, ManualReason.MULTIPLE_LITERALS)

    safe: list[ast.Constant] = []
    for node in matching:
        parent = parents.get(node)
        unsafe = _ambiguous_parent(node, parent)
        if unsafe is not None:
            return _python_failure(file, source, line, variable, unsafe)
        if _annotation_context(node, parents):
            return _python_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
        if _environment_key_context(node, parents):
            return _python_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
        if _python_code_evaluation_context(node, parents):
            # ``eval("NOM")`` : la valeur d'env serait ré-évaluée comme du code.
            return _python_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
        if node.end_lineno != line:
            return _python_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
        try:
            segment = ast.get_source_segment(source, node)
        except (ValueError, TypeError, MemoryError, RecursionError):
            segment = None
        if segment is None or not _single_string_token(segment):
            return _python_failure(
                file, source, line, variable, ManualReason.AMBIGUOUS_CONCATENATION
            )
        safe.append(node)

    if len(safe) != 1:
        return _python_failure(file, source, line, variable, ManualReason.MULTIPLE_LITERALS)

    module_import, shadowed = _python_os_status(tree, line)
    if shadowed:
        return _python_failure(file, source, line, variable, ManualReason.SHADOWED_MODULE)

    node = safe[0]
    raw_line = lines[line - 1]
    suffix = "\r" if raw_line.endswith("\r") else ""
    content = raw_line[: -len(suffix)] if suffix else raw_line
    start = _utf8_column_to_char(content, node.col_offset)
    end_column = node.end_col_offset
    end = None if end_column is None else _utf8_column_to_char(content, end_column)
    if start is None or end is None or start >= end or end > len(content):
        return _python_failure(file, source, line, variable, ManualReason.INVALID_SYNTAX)
    segment = content[start:end]
    if not _single_string_token(segment):
        return _python_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONCATENATION)
    expression = replacement_expression(Language.PYTHON, variable)
    before = content[:start]
    if before and (before[-1].isalnum() or before[-1] in _PYTHON_IDENT_EXTRA):
        expression = " " + expression
    patched_line = before + expression + content[end:] + suffix
    replaced = "\n".join([*lines[: line - 1], patched_line, *lines[line:]])
    try:
        ast.parse(replaced)
    except (SyntaxError, ValueError, TypeError, UnicodeError, MemoryError, RecursionError):
        return _python_failure(file, source, line, variable, ManualReason.INVALID_SYNTAX)

    import_added = False
    line_after = line
    final = replaced
    if not module_import:
        inserted = _with_python_import(replaced, line)
        if inserted is None:
            return _python_failure(file, source, line, variable, ManualReason.INVALID_SYNTAX)
        final, line_after = inserted
        import_added = True
    return ReplacementPlan(
        file=file,
        line=line,
        language=Language.PYTHON,
        variable=variable,
        before=source,
        after=final,
        expression=replacement_expression(Language.PYTHON, variable),
        manual_remediation=False,
        reason=None,
        import_added=import_added,
        line_after=line_after,
    )


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _JsToken:
    kind: str
    # ``value`` contient la valeur **décodée** d'une chaîne : comme ``text``,
    # elle est exclue de ``repr`` pour qu'une traceback ne journalise jamais le
    # secret (invariant 8).
    value: str | None = field(repr=False)
    start: int
    end: int
    line: int
    end_line: int
    text: str = field(repr=False)


class _JsSyntax(Exception):
    """Échec de tokenisation interne : jamais rendu à l'appelant."""


_REGEX_PREFIX_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "await",
        "case",
        "delete",
        "do",
        "else",
        "in",
        "instanceof",
        "new",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }
)
_JS_SIMPLE_ESCAPES: Final[dict[str, str]] = {
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "0": "\0",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "`": "`",
}


def _js_identifier_start(character: str) -> bool:
    return character.isalpha() or character in "_$"


def _js_identifier_part(character: str) -> bool:
    return character.isalnum() or character in "_$"


def _advance_line(source: str, index: int, line: int) -> tuple[int, int]:
    """Avance d'un saut de ligne (CRLF compté une fois) sans dépasser la fin."""
    if source[index] == "\r" and index + 1 < len(source) and source[index + 1] == "\n":
        return index + 2, line + 1
    return index + 1, line + 1


def _regex_allowed(previous: _JsToken | None) -> bool:
    if previous is None:
        return True
    if previous.kind == "ident":
        return previous.value in _REGEX_PREFIX_KEYWORDS
    if previous.kind in {"number", "string", "template", "regex"}:
        return False
    if previous.kind == "punct":
        return previous.value not in {")", "]", "}"}
    return True


def _decode_js_string(content: str) -> str | None:  # noqa: PLR0911, PLR0912
    """Décode les échappements JavaScript utiles ; ``None`` = non supporté."""
    output: list[str] = []
    index = 0
    while index < len(content):
        character = content[index]
        if character != "\\":
            output.append(character)
            index += 1
            continue
        index += 1
        if index >= len(content):
            return None
        escape = content[index]
        if escape in _JS_SIMPLE_ESCAPES:
            if escape == "0" and index + 1 < len(content) and content[index + 1].isdigit():
                return None
            output.append(_JS_SIMPLE_ESCAPES[escape])
            index += 1
        elif escape in {"\r", "\n"}:
            if escape == "\r" and index + 1 < len(content) and content[index + 1] == "\n":
                index += 2
            else:
                index += 1
        elif escape == "x":
            if index + 2 >= len(content):
                return None
            try:
                output.append(chr(int(content[index + 1 : index + 3], 16)))
            except ValueError:
                return None
            index += 3
        elif escape == "u":
            if index + 1 < len(content) and content[index + 1] == "{":
                closing = content.find("}", index + 2)
                if closing == -1:
                    return None
                try:
                    code = int(content[index + 2 : closing], 16)
                    output.append(chr(code))
                except (ValueError, OverflowError):
                    return None
                index = closing + 1
            else:
                if index + 4 >= len(content):
                    return None
                try:
                    output.append(chr(int(content[index + 1 : index + 5], 16)))
                except ValueError:
                    return None
                index += 5
        elif escape in "1234567":
            # Octal legacy : refusé plutôt que décodé de façon approximative.
            return None
        else:
            output.append(escape)
            index += 1
    return "".join(output)


def _scan_js_string(source: str, index: int, line: int) -> _JsToken:
    start = index
    start_line = line
    quote = source[index]
    index += 1
    while index < len(source):
        character = source[index]
        if character == "\\":
            if index + 1 >= len(source):
                raise _JsSyntax
            if source[index + 1] in "\r\n":
                index, line = _advance_line(source, index + 1, line)
            else:
                index += 2
            continue
        if character == quote:
            index += 1
            raw = source[start:index]
            return _JsToken(
                "string",
                _decode_js_string(raw[1:-1]),
                start,
                index,
                start_line,
                line,
                raw,
            )
        if character in "\r\n":
            raise _JsSyntax
        index += 1
    raise _JsSyntax


def _scan_js_template(source: str, index: int, line: int) -> _JsToken:
    start = index
    start_line = line
    index += 1
    while index < len(source):
        character = source[index]
        if character == "\\":
            if index + 1 >= len(source):
                raise _JsSyntax
            if source[index + 1] in "\r\n":
                index, line = _advance_line(source, index + 1, line)
            else:
                index += 2
            continue
        if character == "`":
            index += 1
            return _JsToken("template", None, start, index, start_line, line, source[start:index])
        if character in "\r\n":
            index, line = _advance_line(source, index, line)
            continue
        index += 1
    raise _JsSyntax


def _scan_js_regex(source: str, index: int) -> _JsToken:
    start = index
    index += 1
    in_class = False
    escaped = False
    while index < len(source):
        character = source[index]
        if character in "\r\n":
            raise _JsSyntax
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "[":
            in_class = True
        elif character == "]":
            in_class = False
        elif character == "/" and not in_class:
            index += 1
            while index < len(source) and source[index].isalpha():
                index += 1
            return _JsToken("regex", None, start, index, 0, 0, source[start:index])
        index += 1
    raise _JsSyntax


def _tokenize_js(source: str) -> list[_JsToken]:  # noqa: PLR0912, PLR0915
    tokens: list[_JsToken] = []
    index = 0
    line = 1
    previous: _JsToken | None = None
    while index < len(source):
        character = source[index]
        if character == "\ufeff":
            index += 1
            continue
        if index == 0 and source.startswith("#!"):
            newline = source.find("\n", index)
            index = len(source) if newline == -1 else newline
            continue
        if character in "\r\n":
            index, line = _advance_line(source, index, line)
            continue
        if character.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index)
            index = len(source) if newline == -1 else newline
            continue
        if source.startswith("/*", index):
            closing = source.find("*/", index + 2)
            if closing == -1:
                raise _JsSyntax
            cursor = index
            while cursor < closing + 2:
                if source[cursor] in "\r\n":
                    cursor, line = _advance_line(source, cursor, line)
                else:
                    cursor += 1
            index = closing + 2
            continue
        if character in "'\"":
            token = _scan_js_string(source, index, line)
        elif character == "`":
            token = _scan_js_template(source, index, line)
        elif character == "/":
            if _regex_allowed(previous):
                token = _scan_js_regex(source, index)
                token = _JsToken(
                    token.kind,
                    token.value,
                    token.start,
                    token.end,
                    line,
                    line,
                    token.text,
                )
            else:
                token = _JsToken("punct", "/", index, index + 1, line, line, "/")
                index += 1
        elif _js_identifier_start(character):
            end = index + 1
            while end < len(source) and _js_identifier_part(source[end]):
                end += 1
            token = _JsToken("ident", source[index:end], index, end, line, line, source[index:end])
            index = end
        elif character.isdigit():
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] in "._"):
                end += 1
            token = _JsToken("number", source[index:end], index, end, line, line, source[index:end])
            index = end
        else:
            token = _JsToken("punct", character, index, index + 1, line, line, character)
            index += 1
        tokens.append(token)
        if len(tokens) > MAX_JS_TOKENS:
            raise _JsSyntax
        previous = token
        index = token.end
    return tokens


def _js_failure(
    file: str, source: str, line: int, variable: str, reason: ManualReason
) -> ReplacementPlan:
    return _manual(
        file=file,
        source=source,
        line=line,
        variable=variable,
        language=Language.JAVASCRIPT,
        reason=reason,
    )


def _js_needs_space(character: str) -> bool:
    return character.isalnum() or character in "_$"


def _nearest_open_delimiter(tokens: list[_JsToken], position: int) -> str | None:
    """Dernier délimiteur ``{``/``[``/``(`` encore ouvert avant la cible.

    Sert uniquement à distinguer une valeur de tableau/argument (``[``/``(``)
    d'un nom de propriété ou d'un champ de classe (``{``), sans prétendre
    parser JavaScript.
    """
    stack: list[str] = []
    matching = {")": "(", "]": "[", "}": "{"}
    for token in tokens[:position]:
        if token.kind != "punct" or token.value is None:
            continue
        if token.value in "({[":
            stack.append(token.value)
        elif token.value in matching and stack and stack[-1] == matching[token.value]:
            stack.pop()
    return stack[-1] if stack else None


_CALL_NAME_OFFSET: Final[int] = 2
#: Recul nécessaire pour retrouver ``function`` avant ``*`` ou ``process``.
_JS_FUNCTION_KEYWORD_LOOKBACK: Final[int] = 2
#: Recul nécessaire pour reconnaître ``...process`` (rest parameter).
_JS_ELLIPSIS_LOOKBACK: Final[int] = 3
#: Nombre maximal de jetons d'opérateur avant le ``=`` d'une affectation.
_JS_ASSIGNMENT_LOOKBACK: Final[int] = 3

#: Mots-clés dont la parenthèse suivante n'est **pas** une liste de paramètres.
_JS_NON_BINDING_PAREN_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "await",
        "case",
        "delete",
        "do",
        "else",
        "if",
        "import",
        "in",
        "instanceof",
        "new",
        "of",
        "return",
        "switch",
        "throw",
        "typeof",
        "void",
        "while",
        "with",
        "yield",
    }
)
#: Mots-clés qui introduisent une déclaration de nom lié.
_JS_BINDING_KEYWORDS: Final[frozenset[str]] = frozenset(
    {"as", "class", "const", "function", "import", "let", "var"}
)


def _js_delimiters(
    tokens: list[_JsToken],
) -> tuple[list[int | None], dict[int, int]]:
    """Délimiteur ouvrant englobant chaque jeton, et appariements ouverts/fermés."""
    enclosing: list[int | None] = [None] * len(tokens)
    matching: dict[int, int] = {}
    stack: list[int] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for index, token in enumerate(tokens):
        enclosing[index] = stack[-1] if stack else None
        if token.kind != "punct" or token.value is None:
            continue
        if token.value in {"(", "[", "{"}:
            stack.append(index)
        elif token.value in pairs and stack:
            if tokens[stack[-1]].value == pairs[token.value]:
                opening = stack.pop()
                matching[opening] = index
                matching[index] = opening
    return enclosing, matching


def _js_arrow_at(tokens: list[_JsToken], position: int) -> bool:
    """Vrai si les jetons ``position``/``position + 1`` forment une flèche ``=>``."""
    if position + 1 >= len(tokens):
        return False
    first, second = tokens[position], tokens[position + 1]
    return (
        first.kind == "punct"
        and first.value == "="
        and second.kind == "punct"
        and second.value == ">"
        and first.end == second.start
    )


def _js_paren_is_parameter_list(  # noqa: PLR0911 - un refus par contexte
    tokens: list[_JsToken], opening: int, matching: dict[int, int]
) -> bool:
    """Heuristique fermée : la parenthèse ouvre-t-elle des paramètres liés ?

    Une parenthèse non appariée est traitée comme une liste de paramètres :
    le doute profite au refus, jamais au patch.
    """
    closing = matching.get(opening)
    if closing is None:
        return True
    after = tokens[closing + 1] if closing + 1 < len(tokens) else None
    if _js_arrow_at(tokens, closing + 1):
        return True
    previous = tokens[opening - 1] if opening > 0 else None
    if previous is None:
        return False
    if previous.kind == "ident":
        if previous.value in {"catch", "for", "function"}:
            return True
        if previous.value in _JS_NON_BINDING_PAREN_KEYWORDS:
            return False
        # Méthode ou fonction nommée : un corps ``{`` suit la parenthèse.
        return after is not None and after.kind == "punct" and after.value == "{"
    if previous.kind == "punct" and previous.value == "*":
        before_star = (
            tokens[opening - _JS_FUNCTION_KEYWORD_LOOKBACK]
            if opening >= _JS_FUNCTION_KEYWORD_LOOKBACK
            else None
        )
        return (
            before_star is not None
            and before_star.kind == "ident"
            and before_star.value == "function"
        )
    return False


def _js_binding_contexts(
    tokens: list[_JsToken],
    enclosing: list[int | None],
    matching: dict[int, int],
) -> list[bool]:
    """Pour chaque jeton, vrai s'il est dans un motif de liaison/déstructuration.

    Calcul itératif (le parent d'un délimiteur a toujours un indice plus petit)
    pour rester linéaire : un fichier hostile rempli de ``process`` imbriqués ne
    doit pas déclencher un parcours quadratique.
    """
    binding: list[bool] = [False] * len(tokens)
    for index, token in enumerate(tokens):
        if token.kind != "punct" or token.value not in {"(", "[", "{"}:
            continue
        if token.value == "(":
            binding[index] = _js_paren_is_parameter_list(tokens, index, matching)
            continue
        previous = tokens[index - 1] if index > 0 else None
        direct = False
        if previous is not None:
            if previous.kind == "ident" and previous.value in _JS_BINDING_KEYWORDS:
                direct = True
            elif previous.kind == "punct" and previous.value == "(":
                direct = _js_paren_is_parameter_list(tokens, index - 1, matching)
        if not direct:
            closing = matching.get(index)
            if closing is not None and closing + 1 < len(tokens):
                after = tokens[closing + 1]
                if (
                    after.kind == "punct"
                    and after.value == "="
                    and (
                        previous is None
                        or (
                            previous.kind == "punct" and previous.value in {";", "{", "}", "(", ","}
                        )
                    )
                ):
                    # Affectation déstructurante : ``[a] = xs``, ``({a} = obj)``.
                    direct = True
        parent = enclosing[index]
        binding[index] = direct or (parent is not None and binding[parent])
    return [binding[opening] if opening is not None else False for opening in enclosing]


def _js_import_binds_process(tokens: list[_JsToken]) -> bool:
    """Vrai si une clause ``import`` lie le nom ``process``."""
    in_import = False
    for index, token in enumerate(tokens):
        if token.kind == "ident" and token.value == "import":
            previous = tokens[index - 1] if index > 0 else None
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            if previous is not None and previous.kind == "punct" and previous.value == ".":
                continue
            if (
                following is not None
                and following.kind == "punct"
                and following.value in {"(", "."}
            ):
                # ``import(...)`` dynamique ou ``import.meta`` : pas de liaison.
                continue
            in_import = True
            continue
        if not in_import:
            continue
        if token.kind == "string" or (token.kind == "punct" and token.value in {";", "}"}):
            in_import = False
            continue
        if token.kind == "ident" and token.value == "from":
            in_import = False
            continue
        if token.kind == "ident" and token.value == "process":
            return True
    return False


#: Ponctuations pouvant composer une affectation (simple, composée ou update).
_JS_ASSIGNMENT_PUNCT: Final[frozenset[str]] = frozenset(
    {"+", "-", "*", "/", "%", "&", "|", "^", "<", ">", "?"}
)
#: Ponctuation d'entrée d'une affectation, ``=`` compris.
_JS_ASSIGNMENT_START: Final[frozenset[str]] = _JS_ASSIGNMENT_PUNCT | {"="}


def _js_assignment_follows(  # noqa: PLR0911 - un refus par opérateur
    source: str, tokens: list[_JsToken], position: int
) -> bool:
    """Vrai si ``process`` est immédiatement affecté/incrémenté.

    Couvre ``process = ...``, ``process += ...``, ``process++`` et les formes
    composées ; ``==``, ``===``, ``=>``, ``<=`` et ``>=`` restent des lectures.
    """
    if position + 1 >= len(tokens):
        return False
    first = tokens[position + 1]
    if first.kind != "punct" or first.value not in _JS_ASSIGNMENT_START:
        return False
    if first.value == "=":
        # ``==``, ``===`` et ``=>`` ne sont pas des affectations.
        return source[first.end : first.end + 1] not in {"=", ">"}
    cursor = position + 1
    while cursor + 1 < len(tokens) and cursor - position <= _JS_ASSIGNMENT_LOOKBACK:
        current = tokens[cursor]
        following = tokens[cursor + 1]
        if (
            current.kind != "punct"
            or current.value not in _JS_ASSIGNMENT_PUNCT
            or following.kind != "punct"
            or current.end != following.start
        ):
            return False
        if following.value == "=":
            # ``<=``/``>=`` sont des comparaisons, pas des affectations.
            if current.value in {"<", ">"} and cursor == position + 1:
                return False
            return True
        if following.value == current.value and current.value in {"+", "-"}:
            return True
        if current.value in {"<", ">"} and following.value != current.value:
            return False
        cursor += 1
    return False


def _js_process_is_binding(  # noqa: PLR0911 - un refus par contexte
    source: str,
    tokens: list[_JsToken],
    position: int,
    binding: list[bool],
) -> bool:
    """Vrai si ce jeton ``process`` lie (ou écrase) le nom global."""
    previous = tokens[position - 1] if position > 0 else None
    following = tokens[position + 1] if position + 1 < len(tokens) else None
    if previous is not None and previous.kind == "punct" and previous.value == ".":
        ellipsis = (
            position >= _JS_ELLIPSIS_LOOKBACK
            and tokens[position - 2].kind == "punct"
            and tokens[position - 2].value == "."
            and tokens[position - 3].kind == "punct"
            and tokens[position - 3].value == "."
        )
        if not ellipsis:
            # ``obj.process`` n'est pas le nom global.
            return False
    if following is not None and following.kind == "punct" and following.value in {".", "["}:
        # ``process.env`` / ``process["env"]`` : lecture du global, pas une liaison,
        # même à l'intérieur d'une liste de paramètres (valeur par défaut).
        return False
    if (
        following is not None
        and following.kind == "punct"
        and following.value == "?"
        and position + 2 < len(tokens)
        and tokens[position + 2].kind == "punct"
        and tokens[position + 2].value == "."
    ):
        return False
    if previous is not None and previous.kind == "ident":
        if previous.value in _JS_BINDING_KEYWORDS:
            return True
    if (
        previous is not None
        and previous.kind == "punct"
        and previous.value == "*"
        and position >= _JS_FUNCTION_KEYWORD_LOOKBACK
        and tokens[position - _JS_FUNCTION_KEYWORD_LOOKBACK].kind == "ident"
        and tokens[position - _JS_FUNCTION_KEYWORD_LOOKBACK].value == "function"
    ):
        return True
    if following is not None and following.kind == "punct" and following.value == "=":
        if _js_arrow_at(tokens, position + 1):
            return True
    if _js_assignment_follows(source, tokens, position):
        return True
    return binding[position]


def _javascript_process_shadowed(source: str, tokens: list[_JsToken]) -> bool:
    """Vrai si le fichier peut lier ``process`` ailleurs qu'au global Node."""
    if _js_import_binds_process(tokens):
        return True
    enclosing, matching = _js_delimiters(tokens)
    binding = _js_binding_contexts(tokens, enclosing, matching)
    return any(
        token.kind == "ident"
        and token.value == "process"
        and _js_process_is_binding(source, tokens, position, binding)
        for position, token in enumerate(tokens)
    )


def _js_process_env_key(tokens: list[_JsToken], position: int) -> bool:
    """Vrai si le littéral est une clé lue dans ``process.env`` (auto-ciblage).

    Couvre les formes ``process.env["NOM"]``, ``process["env"]["NOM"]``,
    ``process.env.get("NOM")``, ``process["env"].get("NOM")`` et les clés
    d'appel ``Reflect.get(process.env, "NOM")`` : dans chacune, la clé du
    littéral deviendrait la valeur lue, et le patch ``process.env.<VARIABLE>``
    la transformerait en récursion sur la table de secrets.
    """
    if position < 1 or tokens[position - 1].kind != "punct" or tokens[position - 1].value is None:
        # Litéral sans contexte d'indice ni d'appel : pas de clé dynamique.
        return False
    if tokens[position - 1].value not in {"[", "(", ",", ")"}:
        # Litéral en position d'expression simple (``const k = "SECRET"``) :
        # seuls un indice, un appel ou un argument peut être une clé dynamique.
        return False
    end = position - 1
    # Fenêtre glissante **bornée par le délimiteur ouvrant englobant** le
    # littéral, jamais par une distance fixe : un crochet de clé calculée
    # (``process.env[(a0, ..., a14, "SECRET")``) peut se situer à une distance
    # quelconque du littéral dans la limite globale du fichier.
    enclosing_map, _matching_delimiter = _js_delimiters(tokens)
    node = enclosing_map[position]
    while node is not None and not (tokens[node].kind == "punct" and tokens[node].value == "["):
        node = enclosing_map[node]
    start = 0
    if node is not None:
        parent = enclosing_map[node]
        if parent is not None:
            start = parent + 1
    return _js_env_access_present(tokens, start, end)


def _js_normalize_optional_chaining(tokens: list[_JsToken], start: int, end: int) -> list[_JsToken]:
    """Fusionne les sauts optionnels avant analyse : ``?.`` et ``?[``.

    ``?`` suivi de ``.`` (``a?.b``) fusionne en saut membre, ``?`` suivi de ``[``
    (``a?.[b]``) fusionne en saut indice : l'analyse ne doit pas voir le ``?`` comme
    un séparateur ambigu.
    """
    window = tokens[start:end] if end > start else []
    normalized: list[_JsToken] = []
    cursor = 0
    while cursor < len(window):
        token = window[cursor]
        if (
            token.kind == "punct"
            and token.value == "?"
            and cursor + 1 < len(window)
            and window[cursor + 1].kind == "punct"
            and window[cursor + 1].value in {".", "["}
        ):
            following = window[cursor + 1]
            normalized.append(
                _JsToken(
                    kind="punct",
                    value=following.value,
                    start=token.start,
                    end=following.end,
                    line=token.line,
                    end_line=token.end_line,
                    text=following.value or "",
                )
            )
            cursor += 2
            continue
        normalized.append(token)
        cursor += 1
    return normalized


def _js_env_access_present(tokens: list[_JsToken], start: int, end: int) -> bool:
    """Vrai si la plage ``[start, end)`` contient un accès ``process.env``.

    Détecte les lectures par membre (``process.env``, ``process.env.FOO``) et
    par indice (``process["env"]``), y compris avec chaînage optionnel
    (``process?.env``, ``process?.env?.get``, ``process?.["env"]``,
    ``process?.[...]``) : la séquence optionnelle ``?`` + ``.``/``[`` est fusionnée
    avant l'analyse, de sorte que ``process?.env`` soit vu comme un saut membre
    classique et ``process?.[...]`` comme un saut indice. L'analyse reste une
    fenêtre glissante : le doute profite au refus, jamais au patch.
    """
    normalized = _js_normalize_optional_chaining(tokens, start, end)
    for position, token in enumerate(normalized):
        if token.kind not in {"ident", "string"} or token.value != "env":
            continue
        previous = normalized[position - 1] if position > 0 else None
        if (
            previous is not None
            and previous.kind == "punct"
            and previous.value == "."
            and position - 2 >= 0
            and normalized[position - 2].kind == "ident"
            and normalized[position - 2].value == "process"
        ):
            # Membre : ``process.env`` ou un sous-récepteur déjà env-rooted.
            # La fusion ``?.`` a rendu l'accès membre lisible.
            return True
        if (
            previous is not None
            and previous.kind == "punct"
            and previous.value == "["
            and position + 1 < len(normalized)
            and normalized[position + 1].kind == "punct"
            and normalized[position + 1].value == "]"
            and position - 2 >= 0
            and normalized[position - 2].kind == "ident"
            and normalized[position - 2].value == "process"
        ):
            # Indice : ``process["env"]`` — le sous-clé est ``env``.
            return True
    return False


def _js_computed_process_key(tokens: list[_JsToken], position: int) -> bool:
    """Vrai si le littéral est une clé de propriété **calculée** ``process[...]``.

    ``process["en" + "v"]["APP_KEY"]`` : la fenêtre glissante ne peut pas
    prouver, à partir du seul littéral, que la clé remontée est ``env``. Le doute
    profite au refus : un accès membre calculé sur ``process`` est ambigu.

    Le saut optionnel compte : ``process?.[KEY]`` est un accès par indice comme
    ``process[KEY]``, la clé étant une expression dont la fenêtre littérale ne
    suffit pas à prouver la racine ``env``. De même, toute clé dont le
    délimiteur ouvrant englobant est un crochet ``[...]`` et dont le récepteur
    mentionne ``process`` (membre ou indice) déclenche le refus. La recherche
    part du délimiteur englobant, et non d'une distance fixe : la clé peut se
    trouver à une profondeur variable dans la limite globale du fichier.
    """
    previous = tokens[position - 1] if position > 0 else None
    if previous is None or previous.kind != "punct" or previous.value not in {"[", "(", ",", ")"}:
        # Littéral hors position de clé : simple valeur (``const k = "SECRET"``),
        # pas une clé remontée ; seules les lectures dynamiques restent bloquées.
        return False
    enclosing_map, _matching_delimiter = _js_delimiters(tokens)
    opener = enclosing_map[position]
    while opener is not None and not (
        tokens[opener].kind == "punct" and tokens[opener].value == "["
    ):
        opener = enclosing_map[opener]
    if opener is None:
        # Le littéral n'est pas posé sur une clé de propriété calculée : les
        # arguments d'appel (``f("SECRET")``) et les éléments de tableau
        # (``["SECRET"]``) restent des positions d'expression éligibles au patch.
        return False
    normalized = _js_normalize_optional_chaining(tokens, 0, opener)
    for index, token in enumerate(normalized):
        if (
            token.kind == "ident"
            and token.value == "process"
            and index + 1 < len(normalized)
            and normalized[index + 1].kind == "punct"
            and normalized[index + 1].value in {".", "["}
        ):
            # Accès membre (``process.env…``) ou par indice (``process[...]``,
            # ``process?.[...]``) : la clé remonte une expression dynamique.
            return True
    return False


def _js_standalone_string(tokens: list[_JsToken], position: int) -> bool:
    """Vrai pour une chaîne en position d'instruction (directive prologue)."""
    token = tokens[position]
    previous = tokens[position - 1] if position > 0 else None
    following = tokens[position + 1] if position + 1 < len(tokens) else None
    if previous is None:
        before = True
    elif previous.kind == "punct" and previous.value in {";", "{", "}"}:
        before = True
    elif previous.kind == "string" and previous.line < token.line:
        # Chaîne de directives juxtaposées par ASI : ``"use strict"\n"autre"``.
        before = True
    else:
        before = False
    if following is None:
        after = True
    elif following.kind == "punct" and following.value in {";", "}"}:
        after = True
    else:
        after = following.line > token.end_line
    return before and after


#: Appels JS dont le premier argument chaîne serait évalué comme du code.
_JS_EVAL_CALLEES: Final[frozenset[str]] = frozenset(
    {"eval", "Function", "compile", "setTimeout", "setInterval"}
)

#: Longueur du suffixe ``, eval`` qui signe un appel indirect ``(0, eval)(...)``.
_INDIRECT_EVAL_SUFFIX_LEN: Final[int] = 2


def _js_code_evaluation_call(tokens: list[_JsToken], position: int) -> bool:
    """Vrai si le littéral est le premier argument d'un appel d'évaluation.

    Couvre les formes directes (``eval("NOM")``), optionnelles
    (``eval?.("NOM")``, ``Function?.("NOM")`` — le ``?`` est sauté avant le
    test) et indirectes (``(0, eval)("NOM")`` — séquence ``,`` + ident +
    ``)`` + ``(``). Dans chaque cas la valeur d'environnement serait
    ré-évaluée comme du code : le doute profite au refus.
    """
    previous = tokens[position - 1] if position > 0 else None
    if previous is None or previous.kind != "punct" or previous.value != "(":
        return False
    cursor = position - _CALL_NAME_OFFSET
    while cursor >= 0 and tokens[cursor].kind == "punct" and tokens[cursor].value in {"?", "."}:
        # Appel optionnel : ``eval?.(`` est tokenizé ``eval ? . (`` — le
        # ``?.`` ne change pas le callee.
        cursor -= 1
    if cursor >= 0 and tokens[cursor].kind == "ident" and tokens[cursor].value in _JS_EVAL_CALLEES:
        return True
    closer = position - _CALL_NAME_OFFSET
    if closer >= 0 and tokens[closer].kind == "punct" and tokens[closer].value == ")":
        # Appel indirect : ``(0, eval)("NOM")`` — le ``(`` du littéral ferme
        # un groupe dont le dernier membre est ``, eval``.
        depth = 0
        opener = closer
        while opener >= 0:
            candidate = tokens[opener]
            if candidate.kind == "punct":
                if candidate.value == ")":
                    depth += 1
                elif candidate.value == "(":
                    depth -= 1
                    if depth == 0:
                        break
            opener -= 1
        if opener >= 0:
            inner = [
                token
                for token in tokens[opener + 1 : closer]
                if not (token.kind == "punct" and token.value == "?")
            ]
            if (
                len(inner) >= _INDIRECT_EVAL_SUFFIX_LEN
                and inner[-2].kind == "punct"
                and inner[-2].value == ","
                and inner[-1].kind == "ident"
                and inner[-1].value in _JS_EVAL_CALLEES
            ):
                return True
    return False


def _javascript_replacement(  # noqa: PLR0911, PLR0912 - un refus par garde
    file: str, source: str, line: int, secret: str, variable: str
) -> ReplacementPlan:
    if line > source.count("\n") + 1:
        return _js_failure(file, source, line, variable, ManualReason.STALE_LINE)
    try:
        tokens = _tokenize_js(source)
    except _JsSyntax:
        return _js_failure(file, source, line, variable, ManualReason.INVALID_SYNTAX)

    candidates: list[tuple[int, _JsToken]] = []
    template_seen = False
    for position, token in enumerate(tokens):
        if token.kind == "template" and secret in token.text and token.line == line:
            template_seen = True
        if token.kind == "string" and token.value == secret and token.line == line:
            candidates.append((position, token))

    if template_seen:
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_STRING)
    if not candidates:
        line_text = source.split("\n")[line - 1]
        reason = (
            ManualReason.NO_SIMPLE_LITERAL if secret in line_text else ManualReason.SECRET_NOT_FOUND
        )
        return _js_failure(file, source, line, variable, reason)
    if len(candidates) != 1:
        return _js_failure(file, source, line, variable, ManualReason.MULTIPLE_LITERALS)

    position, token = candidates[0]
    if _javascript_process_shadowed(source, tokens):
        return _js_failure(file, source, line, variable, ManualReason.SHADOWED_MODULE)
    if _js_process_env_key(tokens, position):
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
    if _js_computed_process_key(tokens, position):
        # Clé de propriété calculée (``process["en" + "v"]…``) : la fenêtre
        # littérale seule ne prouve pas la clé ``env`` — le doute profite au refus.
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
    if _js_standalone_string(tokens, position):
        # Directive prologue (``"use strict"``) : remplacer le littéral ferait
        # perdre la sémantique de directive.
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
    if token.end_line != token.line:
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
    previous = tokens[position - 1] if position > 0 else None
    following = tokens[position + 1] if position + 1 < len(tokens) else None
    if (previous is not None and previous.kind == "string") or (
        following is not None and following.kind == "string"
    ):
        # Concaténation implicite : ``"SECRET" "other"`` n'est pas du JS valide,
        # mais le tokenizer le réduit à deux jetons ``string`` contigus. Sans
        # cette garde, le patch produirait ``process.env.APP_KEY "other"`` sur
        # une entrée déjà invalide, sans revalidation possible côté tokenizer.
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONCATENATION)
    if (previous is not None and previous.kind == "punct" and previous.value == "+") or (
        following is not None and following.kind == "punct" and following.value == "+"
    ):
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONCATENATION)
    if (
        previous is not None
        and previous.kind == "ident"
        and previous.value
        in {
            "from",
            "import",
        }
    ):
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
    if (
        previous is not None
        and previous.kind == "punct"
        and previous.value == "("
        and position >= _CALL_NAME_OFFSET
        and tokens[position - _CALL_NAME_OFFSET].kind == "ident"
        and tokens[position - _CALL_NAME_OFFSET].value in {"require", "import"}
    ):
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
    if _js_code_evaluation_call(tokens, position):
        # ``eval("NOM")`` / ``Function("NOM")`` / ``compile("NOM")``,
        # ``setTimeout("NOM", ...)``, formes optionnelles (``eval?.(...)``) et
        # indirectes (``(0, eval)(...)``) : la valeur d'environnement serait
        # ré-évaluée comme du code source. Le doute profite au refus, jamais
        # au remplacement.
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
    if (
        following is not None
        and following.kind == "punct"
        and following.value == ":"
        and previous is not None
        and previous.kind == "punct"
        and previous.value in {"{", ","}
    ):
        # Clé d'objet littérale : ``{"secret": 1}`` ne peut pas devenir
        # ``{process.env.X: 1}`` sans changer la grammaire (clé calculée).
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
    if (
        previous is not None
        and previous.kind == "punct"
        and previous.value in {"{", ",", ";", "}"}
        and _nearest_open_delimiter(tokens, position) == "{"
    ):
        # Champ de classe sans initialiseur (``class X { "secret" }``) ou
        # expression de bloc : la position est un nom de propriété, pas une
        # valeur. Un tableau ou des arguments (délimiteur ``[``/``(``) restent
        # éligibles.
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
    if following is not None and following.kind == "punct" and following.value == "(":
        # Nom de méthode littéral (``{"secret"() {}}``, ``class { "secret"() {} }``)
        # ou appel d'une chaîne : la substitution par un identifiant est ambiguë.
        return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)
    if following is not None and following.kind == "punct" and following.value == "=":
        # Champ de classe littéral ``class X { "secret" = 1 }``. Un ``==`` ou
        # ``===`` reste une comparaison légitime : on regarde le caractère
        # immédiatement après le premier ``=``.
        if source[following.end : following.end + 1] not in {"=", ">"}:
            return _js_failure(file, source, line, variable, ManualReason.AMBIGUOUS_CONTEXT)

    expression = replacement_expression(Language.JAVASCRIPT, variable)
    if token.start > 0 and _js_needs_space(source[token.start - 1]):
        expression = " " + expression
    if token.end < len(source) and _js_needs_space(source[token.end]):
        expression += " "
    patched = source[: token.start] + expression + source[token.end :]
    return ReplacementPlan(
        file=file,
        line=line,
        language=Language.JAVASCRIPT,
        variable=variable,
        before=source,
        after=patched,
        expression=replacement_expression(Language.JAVASCRIPT, variable),
        manual_remediation=False,
        reason=None,
        import_added=False,
        line_after=line,
    )
