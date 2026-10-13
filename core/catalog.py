"""Loads every recipe module (in dependency order) so templates.TEMPLATES holds the full catalog."""
from core import (recipes, recipes_compute, recipes_containers, recipes_lambda, recipes_network,
                  recipes_storage)

MODULES = (recipes, recipes_compute, recipes_containers, recipes_network, recipes_storage, recipes_lambda)
