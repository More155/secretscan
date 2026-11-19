"""Modelos de datos compartidos por todas las capas de secretscan."""

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field

from secretscan.masking import mask_secret


class Severity(StrEnum):
    """Nivel de gravedad de un hallazgo.

    Attributes:
        HIGH: Patrón específico confirmado (por ejemplo, una clave de AWS).
        MEDIUM: Patrón genérico con contexto (ej.: ``password = "..."``).
        LOW: Solo alta entropía, sin ningún contexto que lo respalde.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(BaseModel):
    """Posible secreto encontrado en un archivo o en un commit.

    Un hallazgo nunca guarda el secreto original, solo una versión
    enmascarada. Conviene crearlo con ``Finding.from_secret`` para que
    el enmascarado ocurra automáticamente.

    Attributes:
        rule_id: Identificador de la regla que detectó el secreto.
        severity: Gravedad del hallazgo.
        file_path: Ruta del archivo donde se encontró el secreto.
        line: Número de línea, empezando en 1.
        masked_value: El secreto, ya enmascarado.
        commit: Hash del commit, solo en escaneos de historial.
        author: Autor del commit, solo en escaneos de historial.
        date: Fecha del commit, solo en escaneos de historial.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Field(min_length=1)
    severity: Severity
    file_path: str = Field(min_length=1)
    line: int = Field(ge=1)
    masked_value: str
    commit: str | None = None
    author: str | None = None
    date: datetime | None = None

    @classmethod
    def from_secret(
        cls,
        *,
        secret: str,
        rule_id: str,
        severity: Severity,
        file_path: str,
        line: int,
        commit: str | None = None,
        author: str | None = None,
        date: datetime | None = None,
    ) -> Self:
        """Crea un hallazgo a partir de un secreto crudo, enmascarándolo.

        El ``secret`` original se enmascara de inmediato y no se guarda.

        Args:
            secret: El valor secreto tal como se detectó.
            rule_id: Identificador de la regla que detectó el secreto.
            severity: Gravedad del hallazgo.
            file_path: Ruta del archivo donde se encontró el secreto.
            line: Número de línea, empezando en 1.
            commit: Hash del commit, solo en escaneos de historial.
            author: Autor del commit, solo en escaneos de historial.
            date: Fecha del commit, solo en escaneos de historial.

        Returns:
            Un nuevo ``Finding`` inmutable.
        """
        return cls(
            rule_id=rule_id,
            severity=severity,
            file_path=file_path,
            line=line,
            masked_value=mask_secret(secret),
            commit=commit,
            author=author,
            date=date,
        )
