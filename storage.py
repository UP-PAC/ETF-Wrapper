from __future__ import annotations

"""storage.py

Obiettivo:
- Offrire una singola API (UserStorage) usata dall'app, indipendente dal backend.
- Oggi: backend filesystem (sviluppo/demo).
- Domani: backend PostgreSQL + object storage (produzione B2C), SENZA cambiare la UI.

Uso nell'app:
    from storage import UserStorage
    store = UserStorage(base_dir=Path(...))   # default: filesystem

Switch backend (futuro):
- via env:  UW_STORAGE_BACKEND=postgres
- via secrets: [storage] backend="postgres"
e poi configurare i parametri (DB, bucket, ecc.).
"""

from dataclasses import dataclass
from pathlib import Path
import hashlib
import pickle
from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class StorageBackend(Protocol):
    def load(self, user_id: str, key: str, default: Any = None) -> Any: ...
    def save(self, user_id: str, key: str, obj: Any) -> None: ...
    def delete(self, user_id: str, key: str) -> None: ...


@dataclass
class FileSystemBackend:
    """Backend su filesystem.

    - Isola i dati per utente tramite cartelle separate (hash, nessuna email in chiaro).
    - Adatto a sviluppo e demo.
    - NON adatto a produzione multi-istanza / multi-utente senza ulteriore infrastruttura.
    """
    base_dir: Path

    def __post_init__(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _user_dir(self, user_id: str) -> Path:
        h = hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:16]
        d = self.base_dir / h
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _path(self, user_id: str, key: str) -> Path:
        safe_key = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in key)
        return self._user_dir(user_id) / f"{safe_key}.pkl"

    def load(self, user_id: str, key: str, default: Any = None) -> Any:
        p = self._path(user_id, key)
        try:
            if p.exists():
                with open(p, "rb") as f:
                    return pickle.load(f)
        except Exception:
            return default
        return default

    def save(self, user_id: str, key: str, obj: Any) -> None:
        p = self._path(user_id, key)
        try:
            with open(p, "wb") as f:
                pickle.dump(obj, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            # in caso di permessi / filesystem read-only, non bloccare la app
            pass

    def delete(self, user_id: str, key: str) -> None:
        p = self._path(user_id, key)
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


@dataclass
class PostgresObjectBackend:
    """Stub del backend Produzione: PostgreSQL + Object Storage.

    Implementazione prevista:
    - PostgreSQL: metadati (chiave, user_id, versione, checksum, created_at, ecc.).
    - Object storage (S3/Azure/GCS): payload grandi (es. DataFrame serializzati in Parquet).

    Nota:
    - Non viene attivato di default.
    - Se selezionato senza dipendenze/config, solleva errore esplicativo.
    """

    dsn: str
    bucket: str
    prefix: str = "uw"

    def _not_configured(self) -> None:
        raise RuntimeError(
            "Backend 'postgres' non configurato in questa build. " 
            "Predisposto per futura migrazione: aggiungere dipendenze (psycopg/SQLAlchemy + client S3/Azure/GCS) " 
            "e implementare PostgresObjectBackend.load/save/delete."
        )

    def load(self, user_id: str, key: str, default: Any = None) -> Any:
        self._not_configured()

    def save(self, user_id: str, key: str, obj: Any) -> None:
        self._not_configured()

    def delete(self, user_id: str, key: str) -> None:
        self._not_configured()


@dataclass
class UserStorage:
    """Facade usata dall'app. L'API rimane stabile, cambia solo il backend."""
    base_dir: Optional[Path] = None
    backend: str = "filesystem"

    # parametri futuri (postgres)
    dsn: Optional[str] = None
    bucket: Optional[str] = None
    prefix: str = "uw"

    _impl: StorageBackend | None = None

    def __post_init__(self) -> None:
        b = (self.backend or "filesystem").strip().lower()
        if b in ("filesystem", "fs", "file"):
            if self.base_dir is None:
                raise ValueError("Per backend filesystem serve base_dir")
            self._impl = FileSystemBackend(self.base_dir)
        elif b in ("postgres", "pg", "postgresql"):
            if not self.dsn or not self.bucket:
                raise ValueError("Per backend postgres servono dsn e bucket")
            self._impl = PostgresObjectBackend(dsn=self.dsn, bucket=self.bucket, prefix=self.prefix)
        else:
            raise ValueError(f"Backend storage non supportato: {self.backend}")

    def load(self, user_id: str, key: str, default: Any = None) -> Any:
        assert self._impl is not None
        return self._impl.load(user_id, key, default)

    def save(self, user_id: str, key: str, obj: Any) -> None:
        assert self._impl is not None
        self._impl.save(user_id, key, obj)

    def delete(self, user_id: str, key: str) -> None:
        assert self._impl is not None
        self._impl.delete(user_id, key)
