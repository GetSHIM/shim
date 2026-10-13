"""Tenant policy kept in a signed YAML file instead of the panel."""

# What a file can manage; a tenant in file mode picks a non-empty subset.
FILE_MANAGEABLE = ("privacy", "gateway_settings", "rules")
