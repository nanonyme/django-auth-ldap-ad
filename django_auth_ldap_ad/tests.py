from __future__ import absolute_import
from ldap3 import MOCK_ASYNC
from . import backend

from django.test import TestCase
import unittest

from django.contrib.auth.models import User, Group


class TestSettings(backend.LDAPSettings):

    def __init__(self, **kwargs):
        for name, default in self.defaults.items():
            value = kwargs.get(name, default)
            setattr(self, name, value)


class LDAPBackendTest(TestCase):
    top = ('o=test', {'o': 'test'})
    alice = ('cn=alice,ou=example,o=test',
             {'SAMAccountName': ['alice'],
              'userPassword': ['alicepw'],
              'memberOf': ["dc=test,cn=admin,cn=extra,cn=fake,ou=foo",
                           "dc=test,cn=superuser,cn=extra,cn=fake,ou=foo",
                           "dc=test,cn=fakuser,cn=extra,cn=fake,ou=foo"]})

    def _connection_hook(self, connection):
        connection.strategy.add_entry(self.alice)

    def _init_settings(self, **kwargs):
        ldap_settings = TestSettings(**kwargs)
        self.backend = backend.LDAPBackend(client_strategy=MOCK_ASYNC,
                                           ldap_settings=ldap_settings,
                                           connection_hook=self._connection_hook)

    @unittest.expectedFailure
    def test_options(self):
        self._init_settings(
            SEARCH_DN="o=test",
            CONNECTION_OPTIONS={'opt1': 'value1'}
        )
        self.backend.authenticate(username='alice', password='alicepw')
        self.assertEqual(self.ldapobj.get_option('opt1'), 'value1')

    def test_server_uri_string(self):
        self._init_settings(
            SEARCH_DN="o=test",
            SERVER_URI="ldap://localhost/"
        )
        self.backend.authenticate(username='alice', password='alicepw')

    def test_server_uri_list(self):
        self._init_settings(
            SEARCH_DN="o=test",
            SERVER_URI=["ldap://127.0.0.1", "ldap://localhost/"]
        )
        self.backend.authenticate(username='alice', password='alicepw')

    def test_bad_person(self):
        self._init_settings(
            SEARCH_DN="o=test",
        )
        self.assertEqual(User.objects.filter(username="veikko").count(), 0)
        self.backend.authenticate(username='veikko', password='alicepw')
        self.assertEqual(User.objects.filter(username="veikko").count(), 0)

    # Well this would be nice, but since we dont have bind its not going to hapen
    # def test_bad_password(self):

    def test_user_creation(self):
        self._init_settings(
            SEARCH_DN="o=test",
        )
        self.assertEqual(User.objects.filter(username="alice").count(), 0)
        self.backend.authenticate(username='alice', password='alicepw')
        self.assertEqual(User.objects.filter(username="alice").count(), 1)
        self.backend.authenticate(username='alice', password='alicepw')
        self.assertEqual(User.objects.filter(username="alice").count(), 1)

    def test_user_properties(self):
        self._init_settings(
            SEARCH_DN="o=test",
            USER_ATTR_MAP={'first_name': 'userPassword'}
        )
        self.backend.authenticate(username='alice', password='alicepw')
        user_alice = User.objects.get(username="alice")
        self.assertEqual(user_alice.first_name, 'alicepw')

    def test_user_flags_000(self):
        self._init_settings(
            SEARCH_DN="o=test",
            USER_FLAGS_BY_GROUP={'is_superuser': 'cn=superuser',
                                 'is_staff': 'cn=is_staff_not_found'}
        )

        self.backend.authenticate(username='alice', password='alicepw')
        user_alice = User.objects.get(username="alice")
        self.assertEqual(user_alice.is_superuser, True)
        self.assertEqual(user_alice.is_staff, False)

    def test_user_flags_001(self):
        self._init_settings(
            SEARCH_DN="o=test",
            USER_FLAGS_BY_GROUP={
                'is_superuser': 'cn=superuser,dc=test_not_found',
                'is_staff': 'cn=fake,cn=superuser,ou=foo'})

        self.backend.authenticate(username='alice', password='alicepw')
        user_alice = User.objects.get(username="alice")
        self.assertEqual(user_alice.is_superuser, False)
        self.assertEqual(user_alice.is_staff, True)

    def test_user_flags_002(self):
        self._init_settings(
            SEARCH_DN="o=test",
            USER_FLAGS_BY_GROUP={
                'is_superuser': [
                    'cn=superuser,dc=test_not_found',
                    'cn=fake,cn=superuser,ou=foo']})

        self.backend.authenticate(username='alice', password='alicepw')
        user_alice = User.objects.get(username="alice")
        self.assertEqual(user_alice.is_superuser, True)

    def test_user_groups(self):
        group_admin = Group.objects.create(name="MyAdmins")
        Group.objects.create(name="MyPonies")
        self._init_settings(
            SEARCH_DN="o=test",
            USER_GROUPS_BY_GROUP={'MyAdmins': 'cn=superuser,dc=test_not_found',
                                  'MyPonies': 'cn=fake,cn=superuser,ou=foo'}
        )

        self.backend.authenticate(username='alice', password='alicepw')
        user_alice = User.objects.get(username="alice")
        self.assertEqual(user_alice.groups.filter(name="MyAdmins").count(), 0)
        self.assertEqual(user_alice.groups.filter(name="MyPonies").count(), 1)

        # Check also removal
        user_alice.groups.add(group_admin)
        user_alice.save()

        self.assertEqual(user_alice.groups.filter(name="MyAdmins").count(), 1)

        self.backend.authenticate(username='alice', password='alicepw')
        user_alice = User.objects.get(username="alice")
        self.assertEqual(user_alice.groups.filter(name="MyAdmins").count(), 0)
        self.assertEqual(user_alice.groups.filter(name="MyPonies").count(), 1)

    def test_user_groups_001(self):
        """ Test for groups list requirements """
        Group.objects.create(name="MyPonies")
        self._init_settings(
            SEARCH_DN="o=test",
            USER_GROUPS_BY_GROUP={
                'MyPonies': (
                    'cn=superuser,dc=test_not_found',
                    'cn=fake,cn=superuser,ou=foo')})
        self.backend.authenticate(username='alice', password='alicepw')
        user_alice = User.objects.get(username="alice")
        self.assertEqual(user_alice.groups.filter(name="MyPonies").count(), 1)
