from django.db.models.query import QuerySet


class OIDCProviderQuerySet(QuerySet):
    def get_by_natural_key(self, issuer):
        return self.get(issuer=issuer)

OIDCProviderManager = OIDCProviderQuerySet.as_manager


class OIDCClaimMappingQuerySet(QuerySet):
    def get_by_natural_key(self, claim, attribute, verified, required):
        return self.get(claim=claim, attribute=attribute, verified=verified, required=required)

OIDCClaimMappingManager = OIDCClaimMappingQuerySet.as_manager
