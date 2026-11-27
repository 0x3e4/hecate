"""Which advisory vendors may name an SBOM component (app.services.sbom_ecosystem)."""
from __future__ import annotations

import pytest

from app.services.sbom_ecosystem import allowed_vendor_slugs, vendor_names_component


@pytest.mark.parametrize(
    ("purl", "name"),
    [
        (None, "node"),
        ("", "node"),
        ("pkg:generic/node@22.22.3", "node"),
        ("pkg:oci/hecate-backend@sha256%3Aabc", "hecate-backend"),
    ],
)
def test_binary_and_unknown_packages_take_any_vendor(purl, name):
    assert allowed_vendor_slugs(purl, name) is None
    assert vendor_names_component(None, ["nodejs", "Node.js"])


@pytest.mark.parametrize(
    ("purl", "name", "project_vendor"),
    [
        ("pkg:deb/debian/openssl@3.0.15", "openssl", "openssl"),
        ("pkg:apk/alpine/busybox@1.36.1", "busybox", "busybox"),
        ("pkg:rpm/redhat/curl@8.0", "curl", "haxx"),
    ],
)
def test_distribution_packages_take_any_vendor_but_a_registry(purl, name, project_vendor):
    allowed = allowed_vendor_slugs(purl, name)
    assert allowed is not None
    assert vendor_names_component(allowed, [project_vendor])
    assert not vendor_names_component(allowed, ["npm"])


def test_npm_console_is_not_citrix_netscaler_console():
    allowed = allowed_vendor_slugs("pkg:npm/console@0.15.11", "console")
    assert allowed is not None
    assert not vendor_names_component(allowed, ["citrix-netscaler", "Citrix NetScaler"])
    assert vendor_names_component(allowed, ["npm"])
    # NVD writes many npm packages as vendor == product.
    assert vendor_names_component(allowed, ["console"])


@pytest.mark.parametrize(
    ("purl", "name", "vendor"),
    [
        ("pkg:pypi/requests@2.31.0", "requests", "PyPI"),
        ("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0", "log4j-core", "apache"),
        ("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0", "log4j-core", "Maven"),
        ("pkg:golang/github.com/gin-gonic/gin@v1.9.0", "github.com/gin-gonic/gin", "gin-gonic"),
        ("pkg:npm/%40angular/core@17.0.0", "@angular/core", "angular"),
        ("pkg:cargo/serde@1.0.0", "serde", "crates.io"),
        ("pkg:gem/rails@7.1.0", "rails", "RubyGems"),
        ("pkg:composer/symfony/http-kernel@6.0.0", "symfony/http-kernel", "symfony"),
        ("pkg:nuget/Newtonsoft.Json@13.0.1", "Newtonsoft.Json", "NuGet"),
    ],
)
def test_registry_namespace_or_package_names_the_component(purl, name, vendor):
    assert vendor_names_component(allowed_vendor_slugs(purl, name), [vendor])


def test_namespace_noise_does_not_open_the_match():
    allowed = allowed_vendor_slugs("pkg:golang/github.com/gin-gonic/gin@v1.9.0", "github.com/gin-gonic/gin")
    assert allowed is not None
    assert "github" not in allowed and "com" not in allowed


def test_entry_without_vendor_is_not_held_against_the_component():
    allowed = allowed_vendor_slugs("pkg:npm/console@0.15.11", "console")
    assert vendor_names_component(allowed, [])
    assert vendor_names_component(allowed, [None, "  "])
