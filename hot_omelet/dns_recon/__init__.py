"""DNS reconnaissance toolkit for open recursive resolvers.

Dependency-free (pure socket) DNS client + an `OpenResolver` abstraction that
covers fingerprinting, open-recursion detection, DNSSEC-validation detection and
cache snooping (revealing what other clients on a network resolved).
"""
from .resolver import OpenResolver, ResolverProfile, SnoopHit
from . import wordlists

__all__ = ["OpenResolver", "ResolverProfile", "SnoopHit", "wordlists"]
