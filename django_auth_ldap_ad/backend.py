from ldap3 import Server, Connection, SASL, SUBTREE, SYNC
from django.contrib.auth.models import User, Group
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError

import six


class LDAPBackendException(Exception):
    pass

"""
 Main class for handling the authentication
"""


class LDAPBackend(object):

    def __init__(self):
        self.connection = Connection
        self.ldap_settings = LDAPSettings()

    def _generate_servers(self):
        if isinstance(self.ldap_settings.SERVER_URI, six.string_types):
            server_urls = [self.ldap_settings.SERVER_URI]
        else:
            server_urls = self.ldap_settings.SERVER_URI
        self.servers = []
        for server_url in server_urls:
            yield Server(server_url)

    def authenticate(self, username=None, password=None):

        # For all configured servers try to connect
        for server in self._generate_servers():
            try:
                ldap_connection = self.ldap_open_connection(
                    server, username, password)
            except LDAPSocketOpenError:
                continue
            except LDAPInvalidCredentialsResult:
                return None

            # Do search
            try:
                ldap_user_info = self.ldap_search_user(
                    ldap_connection, username, password)
            except LDAPBackendException:
                return None

            return self.get_local_user(username, ldap_user_info)
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def ldap_open_connection(self, server, username, password):
        kwargs = {
            "server": server, "user": username, "password": password,
            "authentication": SASL,
        }
        kwargs.update(self.ldap_settings.CONNECTION_OPTIONS)
        kwargs["client_strategy"] = SYNC
        connection = self.connection(**kwargs)
        connection.bind()
        return connection

    # Search for user, returns users info (dict)
    def ldap_search_user(self, connection, username, password):
        ldap_result_id = connection.search(
            search_base=self.ldap_settings.SEARCH_DN,
            search_scope=SUBTREE,
            search_filter=self.ldap_settings.SEARCH_FILTER % {
                "user": username})
        result_all_type, result_all_data = connection.get_result(ldap_result_id, 1)
        result_entries = []
        for result_type, result_data in result_all_data:
            if result_type is not None:
                result_entries.append(result_data)

        if len(result_entries) == 0:
            raise LDAPBackendException("No entries found!")

        if len(result_entries) != 1:
            raise LDAPBackendException("More than one found!")

        return result_entries[0]

    def get_local_user(self, ldap_username, info):
        username = ldap_username.lower()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # Make new one
            user = User(username=username)
            user.set_unusable_password()
        # refresh memberships
        members_of = []
        for group in info.get('memberOf', []):
            members_of.append(group.lower().split(","))

        # Set first_name or last_name or email ..
        for key, value in self.ldap_settings.USER_ATTR_MAP.items():
            if value in info:
                setattr(user, key, info[value][0])

        def check_for_membership(members_of, required_groups_options):
            """ Check for membership in given groups,
                Parameter:
                   required_groups_options - can be string or list of strings. Each entry must
                                          be comma-separeted groupnames """

            if isinstance(required_groups_options, six.string_types):
                required_groups_options = [required_groups_options]

            for required_groups in required_groups_options:
                required_groups = required_groups.lower().split(",")
                # check for all members of groups
                for member_of_group in members_of:
                    # check that all required groups are in this membership
                    requirement_fullfilled = all(
                        (required_group in member_of_group) for required_group in required_groups)
                    if requirement_fullfilled:
                        return True
            return False

        # set is_superuser etc
        for wanted_property, requirements in self.ldap_settings.USER_FLAGS_BY_GROUP.items():
            has_property = check_for_membership(members_of, requirements)
            setattr(user, wanted_property, has_property)

        # We need to do save before we can use the groups (for m2m binding)
        user.save()
        # user.groups.add( Group.objects.get(name = "ODAdmin"))
        for wanted_group, requirements in self.ldap_settings.USER_GROUPS_BY_GROUP.items():
            if check_for_membership(members_of, requirements):
                user.groups.add(Group.objects.get(name=wanted_group))
            else:
                user.groups.remove(Group.objects.get(name=wanted_group))
        user.save()
        return user


""" Load settings from Django settigns """


class LDAPSettings(object):
    defaults = {
        'CONNECTION_OPTIONS': {},
        'SERVER_URI': 'ldap://localhost',
        'USER_FLAGS_BY_GROUP': {},
        'USER_GROUPS_BY_GROUP': {},
        'USER_ATTR_MAP': {},
        'TRACE_LEVEL': 0,
        'SASL_MECH': 'DIGEST-MD5',
        'SEARCH_DN': "DC=localdomain,DC=ORG",
        'SEARCH_FILTER': "(SAMAccountName=%(user)s)"
    }

    def __init__(self, prefix='AUTH_LDAP_'):
        from django.conf import settings

        for name, default in self.defaults.items():
            value = getattr(settings, prefix + name, default)
            setattr(self, name, value)
