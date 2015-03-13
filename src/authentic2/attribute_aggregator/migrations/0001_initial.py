# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AttributeItem',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('attribute_name', models.CharField(default=(b'OpenLDAProotDSE', b'OpenLDAProotDSE'), max_length=100, verbose_name='Attribute name', choices=[(b'OpenLDAProotDSE', b'OpenLDAProotDSE'), (b'aRecord', b'aRecord'), (b'administrativeRole', b'administrativeRole'), (b'alias', b'alias'), (b'aliasedObjectName', b'aliasedObjectName'), (b'altServer', b'altServer'), (b'associatedDomain', b'associatedDomain'), (b'associatedName', b'associatedName'), (b'attributeTypes', b'attributeTypes'), (b'audio', b'audio'), (b'authPassword', b'authPassword'), (b'authorityRevocationList', b'authorityRevocationList'), (b'authzFrom', b'authzFrom'), (b'authzTo', b'authzTo'), (b'bootFile', b'bootFile'), (b'bootParameter', b'bootParameter'), (b'buildingName', b'buildingName'), (b'businessCategory', b'businessCategory'), (b'c', b'c'), (b'cACertificate', b'cACertificate'), (b'cNAMERecord', b'cNAMERecord'), (b'carLicense', b'carLicense'), (b'certificateRevocationList', b'certificateRevocationList'), (b'children', b'children'), (b'cn', b'cn'), (b'co', b'co'), (b'collectiveAttributeSubentries', b'collectiveAttributeSubentries'), (b'collectiveAttributeSubentry', b'collectiveAttributeSubentry'), (b'collectiveExclusions', b'collectiveExclusions'), (b'configContext', b'configContext'), (b'contextCSN', b'contextCSN'), (b'createTimestamp', b'createTimestamp'), (b'creatorsName', b'creatorsName'), (b'crossCertificatePair', b'crossCertificatePair'), (b'dITContentRules', b'dITContentRules'), (b'dITRedirect', b'dITRedirect'), (b'dITStructureRules', b'dITStructureRules'), (b'dSAQuality', b'dSAQuality'), (b'dc', b'dc'), (b'deltaRevocationList', b'deltaRevocationList'), (b'departmentNumber', b'departmentNumber'), (b'description', b'description'), (b'destinationIndicator', b'destinationIndicator'), (b'displayName', b'displayName'), (b'distinguishedName', b'distinguishedName'), (b'dmdName', b'dmdName'), (b'dnQualifier', b'dnQualifier'), (b'documentAuthor', b'documentAuthor'), (b'documentIdentifier', b'documentIdentifier'), (b'documentLocation', b'documentLocation'), (b'documentPublisher', b'documentPublisher'), (b'documentTitle', b'documentTitle'), (b'documentVersion', b'documentVersion'), (b'drink', b'drink'), (b'dynamicObject', b'dynamicObject'), (b'dynamicSubtrees', b'dynamicSubtrees'), (b'eduOrgHomePageURI', b'eduOrgHomePageURI'), (b'eduOrgIdentityAuthNPolicyURI', b'eduOrgIdentityAuthNPolicyURI'), (b'eduOrgLegalName', b'eduOrgLegalName'), (b'eduOrgSuperiorURI', b'eduOrgSuperiorURI'), (b'eduOrgWhitePagesURI', b'eduOrgWhitePagesURI'), (b'eduPersonAffiliation', b'eduPersonAffiliation'), (b'eduPersonAssurance', b'eduPersonAssurance'), (b'eduPersonEntitlement', b'eduPersonEntitlement'), (b'eduPersonNickname', b'eduPersonNickname'), (b'eduPersonOrgDN', b'eduPersonOrgDN'), (b'eduPersonOrgUnitDN', b'eduPersonOrgUnitDN'), (b'eduPersonPrimaryAffiliation', b'eduPersonPrimaryAffiliation'), (b'eduPersonPrimaryOrgUnitDN', b'eduPersonPrimaryOrgUnitDN'), (b'eduPersonPrincipalName', b'eduPersonPrincipalName'), (b'eduPersonScopedAffiliation', b'eduPersonScopedAffiliation'), (b'eduPersonTargetedID', b'eduPersonTargetedID'), (b'email', b'email'), (b'employeeNumber', b'employeeNumber'), (b'employeeType', b'employeeType'), (b'enhancedSearchGuide', b'enhancedSearchGuide'), (b'entry', b'entry'), (b'entryCSN', b'entryCSN'), (b'entryDN', b'entryDN'), (b'entryTtl', b'entryTtl'), (b'entryUUID', b'entryUUID'), (b'extensibleObject', b'extensibleObject'), (b'fax', b'fax'), (b'gecos', b'gecos'), (b'generationQualifier', b'generationQualifier'), (b'gidNumber', b'gidNumber'), (b'givenName', b'givenName'), (b'glue', b'glue'), (b'hasSubordinates', b'hasSubordinates'), (b'homeDirectory', b'homeDirectory'), (b'homePhone', b'homePhone'), (b'homePostalAddress', b'homePostalAddress'), (b'host', b'host'), (b'houseIdentifier', b'houseIdentifier'), (b'info', b'info'), (b'initials', b'initials'), (b'internationaliSDNNumber', b'internationaliSDNNumber'), (b'ipHostNumber', b'ipHostNumber'), (b'ipNetmaskNumber', b'ipNetmaskNumber'), (b'ipNetworkNumber', b'ipNetworkNumber'), (b'ipProtocolNumber', b'ipProtocolNumber'), (b'ipServicePort', b'ipServicePort'), (b'ipServiceProtocolSUPname', b'ipServiceProtocolSUPname'), (b'janetMailbox', b'janetMailbox'), (b'jpegPhoto', b'jpegPhoto'), (b'knowledgeInformation', b'knowledgeInformation'), (b'l', b'l'), (b'labeledURI', b'labeledURI'), (b'ldapSyntaxes', b'ldapSyntaxes'), (b'loginShell', b'loginShell'), (b'mDRecord', b'mDRecord'), (b'mXRecord', b'mXRecord'), (b'macAddress', b'macAddress'), (b'mail', b'mail'), (b'mailForwardingAddress', b'mailForwardingAddress'), (b'mailHost', b'mailHost'), (b'mailLocalAddress', b'mailLocalAddress'), (b'mailPreferenceOption', b'mailPreferenceOption'), (b'mailRoutingAddress', b'mailRoutingAddress'), (b'manager', b'manager'), (b'matchingRuleUse', b'matchingRuleUse'), (b'matchingRules', b'matchingRules'), (b'member', b'member'), (b'memberNisNetgroup', b'memberNisNetgroup'), (b'memberUid', b'memberUid'), (b'mobile', b'mobile'), (b'modifiersName', b'modifiersName'), (b'modifyTimestamp', b'modifyTimestamp'), (b'monitorContext', b'monitorContext'), (b'nSRecord', b'nSRecord'), (b'name', b'name'), (b'nameForms', b'nameForms'), (b'namingCSN', b'namingCSN'), (b'namingContexts', b'namingContexts'), (b'nisMapEntry', b'nisMapEntry'), (b'nisMapNameSUPname', b'nisMapNameSUPname'), (b'nisNetgroupTriple', b'nisNetgroupTriple'), (b'o', b'o'), (b'objectClass', b'objectClass'), (b'objectClasses', b'objectClasses'), (b'oncRpcNumber', b'oncRpcNumber'), (b'organizationalStatus', b'organizationalStatus'), (b'otherMailbox', b'otherMailbox'), (b'ou', b'ou'), (b'owner', b'owner'), (b'pager', b'pager'), (b'personalSignature', b'personalSignature'), (b'personalTitle', b'personalTitle'), (b'photo', b'photo'), (b'physicalDeliveryOfficeName', b'physicalDeliveryOfficeName'), (b'postOfficeBox', b'postOfficeBox'), (b'postalAddress', b'postalAddress'), (b'postalCode', b'postalCode'), (b'preferredDeliveryMethod', b'preferredDeliveryMethod'), (b'preferredLanguage', b'preferredLanguage'), (b'presentationAddress', b'presentationAddress'), (b'protocolInformation', b'protocolInformation'), (b'pseudonym', b'pseudonym'), (b'ref', b'ref'), (b'referral', b'referral'), (b'registeredAddress', b'registeredAddress'), (b'rfc822MailMember', b'rfc822MailMember'), (b'role', b'role'), (b'roleOccupant', b'roleOccupant'), (b'roomNumber', b'roomNumber'), (b'sOARecord', b'sOARecord'), (b'schacHomeOrganization', b'schacHomeOrganization'), (b'schacHomeOrganizationType', b'schacHomeOrganizationType'), (b'searchGuide', b'searchGuide'), (b'secretary', b'secretary'), (b'seeAlso', b'seeAlso'), (b'serialNumber', b'serialNumber'), (b'shadowExpire', b'shadowExpire'), (b'shadowFlag', b'shadowFlag'), (b'shadowInactive', b'shadowInactive'), (b'shadowLastChange', b'shadowLastChange'), (b'shadowMax', b'shadowMax'), (b'shadowMin', b'shadowMin'), (b'shadowWarning', b'shadowWarning'), (b'singleLevelQuality', b'singleLevelQuality'), (b'sn', b'sn'), (b'st', b'st'), (b'street', b'street'), (b'structuralObjectClass', b'structuralObjectClass'), (b'subentry', b'subentry'), (b'subschema', b'subschema'), (b'subschemaSubentry', b'subschemaSubentry'), (b'subtreeMaximumQuality', b'subtreeMaximumQuality'), (b'subtreeMinimumQuality', b'subtreeMinimumQuality'), (b'subtreeSpecification', b'subtreeSpecification'), (b'supannActivite', b'supannActivite'), (b'supannAffectation', b'supannAffectation'), (b'supannAliasLogin', b'supannAliasLogin'), (b'supannAutreMail', b'supannAutreMail'), (b'supannAutreTelephone', b'supannAutreTelephone'), (b'supannCivilite', b'supannCivilite'), (b'supannCodeEntite', b'supannCodeEntite'), (b'supannCodeEntiteParent', b'supannCodeEntiteParent'), (b'supannCodeINE', b'supannCodeINE'), (b'supannEmpCorps', b'supannEmpCorps'), (b'supannEmpId', b'supannEmpId'), (b'supannEntiteAffectation', b'supannEntiteAffectation'), (b'supannEntiteAffectationPrincipale', b'supannEntiteAffectationPrincipale'), (b'supannEtablissement', b'supannEtablissement'), (b'supannEtuAnneeInscription', b'supannEtuAnneeInscription'), (b'supannEtuCursusAnnee', b'supannEtuCursusAnnee'), (b'supannEtuDiplome', b'supannEtuDiplome'), (b'supannEtuElementPedagogique', b'supannEtuElementPedagogique'), (b'supannEtuEtape', b'supannEtuEtape'), (b'supannEtuId', b'supannEtuId'), (b'supannEtuInscription', b'supannEtuInscription'), (b'supannEtuRegimeInscription', b'supannEtuRegimeInscription'), (b'supannEtuSecteurDisciplinaire', b'supannEtuSecteurDisciplinaire'), (b'supannEtuTypeDiplome', b'supannEtuTypeDiplome'), (b'supannGroupeAdminDN', b'supannGroupeAdminDN'), (b'supannGroupeDateFin', b'supannGroupeDateFin'), (b'supannGroupeLecteurDN', b'supannGroupeLecteurDN'), (b'supannListeRouge', b'supannListeRouge'), (b'supannMailPerso', b'supannMailPerso'), (b'supannOrganisme', b'supannOrganisme'), (b'supannParrainDN', b'supannParrainDN'), (b'supannRefId', b'supannRefId'), (b'supannRole', b'supannRole'), (b'supannRoleEntite', b'supannRoleEntite'), (b'supannRoleGenerique', b'supannRoleGenerique'), (b'supannTypeEntite', b'supannTypeEntite'), (b'supannTypeEntiteAffectation', b'supannTypeEntiteAffectation'), (b'superiorUUID', b'superiorUUID'), (b'supportedAlgorithms', b'supportedAlgorithms'), (b'supportedApplicationContext', b'supportedApplicationContext'), (b'supportedAuthPasswordSchemes', b'supportedAuthPasswordSchemes'), (b'supportedControl', b'supportedControl'), (b'supportedExtension', b'supportedExtension'), (b'supportedFeatures', b'supportedFeatures'), (b'supportedLDAPVersion', b'supportedLDAPVersion'), (b'supportedSASLMechanisms', b'supportedSASLMechanisms'), (b'syncConsumerSubentry', b'syncConsumerSubentry'), (b'syncProviderSubentry', b'syncProviderSubentry'), (b'syncTimestamp', b'syncTimestamp'), (b'syncreplCookie', b'syncreplCookie'), (b'telephoneNumber', b'telephoneNumber'), (b'teletexTerminalIdentifier', b'teletexTerminalIdentifier'), (b'telexNumber', b'telexNumber'), (b'textEncodedORAddress', b'textEncodedORAddress'), (b'title', b'title'), (b'top', b'top'), (b'uid', b'uid'), (b'uidNumber', b'uidNumber'), (b'uniqueIdentifier', b'uniqueIdentifier'), (b'uniqueMember', b'uniqueMember'), (b'userCertificate', b'userCertificate'), (b'userClass', b'userClass'), (b'userPKCS12', b'userPKCS12'), (b'userPassword', b'userPassword'), (b'userSMIMECertificate', b'userSMIMECertificate'), (b'vendorName', b'vendorName'), (b'vendorVersion', b'vendorVersion'), (b'x121Address', b'x121Address'), (b'x500UniqueIdentifier', b'x500UniqueIdentifier')])),
                ('output_name_format', models.CharField(default=(b'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', b'SAMLv2 URI'), max_length=100, verbose_name='Output name format', choices=[(b'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', b'SAMLv2 URI'), (b'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', b'SAMLv2 BASIC')])),
                ('output_namespace', models.CharField(default=(b'Default', b'Default'), max_length=100, verbose_name='Output namespace', choices=[(b'Default', b'Default'), (b'http://schemas.xmlsoap.org/ws/2005/05/identity/claims', b'http://schemas.xmlsoap.org/ws/2005/05/identity/claims')])),
                ('required', models.BooleanField(default=False, verbose_name='Required')),
            ],
            options={
                'verbose_name': 'attribute list item',
                'verbose_name_plural': 'attribute list items',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='AttributeList',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=100, verbose_name='Name')),
                ('attributes', models.ManyToManyField(related_name='attributes of the list', null=True, verbose_name='Attributes', to='attribute_aggregator.AttributeItem', blank=True)),
            ],
            options={
                'verbose_name': 'attribute list',
                'verbose_name_plural': 'attribute lists',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='AttributeSource',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=200, verbose_name='Name')),
                ('namespace', models.CharField(default=(b'Default', b'Default'), max_length=100, verbose_name='Namespace', choices=[(b'Default', b'Default'), (b'http://schemas.xmlsoap.org/ws/2005/05/identity/claims', b'http://schemas.xmlsoap.org/ws/2005/05/identity/claims')])),
            ],
            options={
                'verbose_name': 'attribute source',
                'verbose_name_plural': 'attribute sources',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='LdapSource',
            fields=[
                ('attributesource_ptr', models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to='attribute_aggregator.AttributeSource')),
                ('server', models.CharField(unique=True, max_length=200, verbose_name='Server')),
                ('user', models.CharField(max_length=200, null=True, verbose_name='User', blank=True)),
                ('password', models.CharField(max_length=200, null=True, verbose_name='Password', blank=True)),
                ('base', models.CharField(max_length=200, verbose_name='Base')),
                ('port', models.IntegerField(default=389, verbose_name='Port')),
                ('ldaps', models.BooleanField(default=False, verbose_name='LDAPS')),
                ('certificate', models.TextField(verbose_name='Certificate', blank=True)),
                ('is_auth_backend', models.BooleanField(default=False, verbose_name='Is it used for authentication?')),
            ],
            options={
                'verbose_name': 'ldap attribute source',
                'verbose_name_plural': 'ldap attribute sources',
            },
            bases=('attribute_aggregator.attributesource',),
        ),
        migrations.CreateModel(
            name='UserAliasInSource',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=200, verbose_name='Name')),
                ('source', models.ForeignKey(verbose_name='attribute source', to='attribute_aggregator.AttributeSource')),
                ('user', models.ForeignKey(related_name='user_alias_in_source', verbose_name='user', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'user alias from source',
                'verbose_name_plural': 'user aliases from source',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='UserAttributeProfile',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('data', models.TextField(null=True, blank=True)),
                ('user', models.OneToOneField(related_name='user_attribute_profile', null=True, blank=True, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'user attribute profile',
                'verbose_name_plural': 'user attribute profiles',
            },
            bases=(models.Model,),
        ),
        migrations.AlterUniqueTogether(
            name='useraliasinsource',
            unique_together=set([('name', 'source')]),
        ),
        migrations.AddField(
            model_name='attributeitem',
            name='source',
            field=models.ForeignKey(verbose_name='Attribute source', blank=True, to='attribute_aggregator.AttributeSource', null=True),
            preserve_default=True,
        ),
    ]
