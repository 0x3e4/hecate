from __future__ import annotations

from pydantic import BaseModel, Field


class CatalogVendor(BaseModel):
    slug: str
    name: str
    aliases: list[str] = Field(default_factory=list)


class CatalogVendorList(BaseModel):
    total: int
    items: list[CatalogVendor]


class CatalogProduct(BaseModel):
    slug: str
    name: str
    vendor_slugs: list[str] = Field(default_factory=list, alias="vendorSlugs", serialization_alias="vendorSlugs")
    aliases: list[str] = Field(default_factory=list)


class CatalogProductList(BaseModel):
    total: int
    items: list[CatalogProduct]


class CatalogVersion(BaseModel):
    id: str
    value: str
    product_slug: str = Field(alias="productSlug", serialization_alias="productSlug")


class CatalogVersionList(BaseModel):
    total: int
    items: list[CatalogVersion]
