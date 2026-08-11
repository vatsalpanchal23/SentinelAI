"""Shared utilities used by the scanner modules.

Deliberately outside of `modules/` so the plugin registry (which treats every
package under `modules/` as a scanner) never tries to load it as a plugin.
"""
