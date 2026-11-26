"""A tiny in-memory stand-in for a Motor collection (only what the tests use).

Supports equality (``None`` also matches a missing field), ``$ne``, ``$in``,
``$nin``, ``$regex``, ``$type: "string"``, ``$or`` and ``$and`` in filters (a scalar condition
matches an element of an array field, as in MongoDB), ``$set`` / ``$unset`` / ``$pull`` updates, ``find`` with
``limit``, ``find_one``, ``insert_one`` (``unique`` fields raise ``DuplicateKeyError``),
``delete_one``, ``update_one`` / ``update_many``, ``replace_one``
(with ``upsert``) and ``bulk_write`` with ``UpdateOne`` / ``UpdateMany``.
Projections are ignored; ``create_index`` is a no-op.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any

from bson import ObjectId


def _equals(value: Any, cond: Any) -> bool:
    if value == cond:
        return True
    return isinstance(value, list) and not isinstance(cond, list) and cond in value


def _any_in(value: Any, arg: Any) -> bool:
    return any(_equals(value, a) for a in arg)


def _matches_value(value: Any, cond: Any) -> bool:
    if isinstance(cond, dict) and any(k.startswith("$") for k in cond):
        for op, arg in cond.items():
            if op == "$ne" and _equals(value, arg):
                return False
            if op == "$in" and not _any_in(value, arg):
                return False
            if op == "$nin" and _any_in(value, arg):
                return False
            if op == "$regex" and not (isinstance(value, str) and re.search(arg, value)):
                return False
            if op == "$type" and not (arg == "string" and isinstance(value, str)):
                return False
        return True
    return _equals(value, cond)


def matches(doc: dict[str, Any], query: dict[str, Any]) -> bool:
    for key, cond in query.items():
        if key == "$or":
            if not any(matches(doc, sub) for sub in cond):
                return False
            continue
        if key == "$and":
            if not all(matches(doc, sub) for sub in cond):
                return False
            continue
        if not _matches_value(doc.get(key), cond):
            return False
    return True


@dataclass
class _Result:
    modified_count: int = 0
    matched_count: int = 0
    upserted_id: Any = None
    deleted_count: int = 0


class _Cursor:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self._docs = docs

    def limit(self, n: int) -> _Cursor:
        return _Cursor(self._docs[:n])

    def skip(self, n: int) -> _Cursor:
        return _Cursor(self._docs[n:])

    def sort(self, *_args: Any, **_kwargs: Any) -> _Cursor:
        return self

    def max_time_ms(self, _ms: int) -> _Cursor:
        return self

    def __aiter__(self):
        async def gen():
            for doc in self._docs:
                yield copy.deepcopy(doc)
        return gen()


class FakeCollection:
    def __init__(self, docs: list[dict[str, Any]] | None = None, unique: tuple[str, ...] = ()) -> None:
        self.unique = unique
        self.docs: list[dict[str, Any]] = []
        for doc in docs or []:
            doc = dict(doc)
            doc.setdefault("_id", ObjectId())
            self.docs.append(doc)

    async def count_documents(self, query: dict[str, Any] | None = None) -> int:
        return sum(1 for d in self.docs if matches(d, query or {}))

    async def create_index(self, *_args: Any, **_kwargs: Any) -> str:
        return "index"

    async def insert_one(self, doc: dict[str, Any]) -> _Result:
        from pymongo.errors import DuplicateKeyError

        doc = copy.deepcopy(doc)
        doc.setdefault("_id", ObjectId())
        for field in ("_id", *self.unique):
            if doc.get(field) is not None and any(d.get(field) == doc[field] for d in self.docs):
                raise DuplicateKeyError(f"duplicate {field}")
        self.docs.append(doc)
        return _Result(upserted_id=doc["_id"])

    async def delete_one(self, query: dict[str, Any]) -> _Result:
        for index, doc in enumerate(self.docs):
            if matches(doc, query):
                del self.docs[index]
                return _Result(matched_count=1, deleted_count=1)
        return _Result()

    def by_id(self, _id: Any) -> dict[str, Any]:
        return next(d for d in self.docs if d["_id"] == _id)

    def find(self, query: dict[str, Any] | None = None, _projection: Any = None, **_kwargs: Any) -> _Cursor:
        return _Cursor([d for d in self.docs if matches(d, query or {})])

    async def find_one(self, query: dict[str, Any] | None = None, _projection: Any = None) -> dict[str, Any] | None:
        for doc in self.docs:
            if matches(doc, query or {}):
                return copy.deepcopy(doc)
        return None

    def _apply(self, query: dict[str, Any], update: dict[str, Any], many: bool) -> _Result:
        result = _Result()
        for doc in self.docs:
            if not matches(doc, query):
                continue
            result.matched_count += 1
            before = dict(doc)
            doc.update(update.get("$set", {}))
            for key in update.get("$unset", {}):
                doc.pop(key, None)
            for key, value in update.get("$pull", {}).items():
                if isinstance(doc.get(key), list):
                    doc[key] = [v for v in doc[key] if v != value]
            if doc != before:
                result.modified_count += 1
            if not many:
                break
        return result

    async def update_one(self, query: dict[str, Any], update: dict[str, Any]) -> _Result:
        return self._apply(query, update, many=False)

    async def update_many(self, query: dict[str, Any], update: dict[str, Any]) -> _Result:
        return self._apply(query, update, many=True)

    async def find_one_and_update(
        self, query: dict[str, Any], update: dict[str, Any], **_kwargs: Any,
    ) -> dict[str, Any] | None:
        """Returns the document after the update (``ReturnDocument.AFTER``)."""
        for doc in self.docs:
            if matches(doc, query):
                self._apply({"_id": doc["_id"]}, update, many=False)
                return copy.deepcopy(doc)
        return None

    async def replace_one(self, query: dict[str, Any], replacement: dict[str, Any], upsert: bool = False) -> _Result:
        for index, doc in enumerate(self.docs):
            if matches(doc, query):
                new = copy.deepcopy(replacement)
                new.setdefault("_id", doc["_id"])
                changed = new != doc
                self.docs[index] = new
                return _Result(modified_count=int(changed), matched_count=1)
        if not upsert:
            return _Result()
        new = copy.deepcopy(replacement)
        new.setdefault("_id", query.get("_id", ObjectId()))
        self.docs.append(new)
        return _Result(upserted_id=new["_id"])

    async def bulk_write(self, ops: list[Any], ordered: bool = True) -> _Result:
        total = _Result()
        for op in ops:
            many = type(op).__name__ == "UpdateMany"
            res = self._apply(op._filter, op._doc, many=many)
            total.modified_count += res.modified_count
            total.matched_count += res.matched_count
        return total
