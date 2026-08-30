from __future__ import annotations

from typing import TYPE_CHECKING

from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from keycloak import KeycloakOpenIDConnection, KeycloakAdmin
from keycloak.exceptions import KeycloakPostError

from tapir.utils.shortcuts import get_from_cache_or_compute

if TYPE_CHECKING:
    from tapir.accounts.models import KeycloakUser


class KeycloakUserManager:
    @classmethod
    def get_keycloak_id_by_email(
        cls, keycloak_client: KeycloakAdmin, email: str
    ) -> str | None:
        """Look up a Keycloak user by email address.

        Returns the Keycloak user ID (UUID), or None if no user has that email.
        Note: Keycloak users may have a `username` that differs from `email`
        (e.g. imported users with `username = customernumber`). Always look up
        by email, never by `keycloak_client.get_user_id(email)` which queries
        by `username`.
        """
        users = keycloak_client.get_users({"email": email, "exact": True})
        if not users:
            return None
        return users[0]["id"]

    @classmethod
    def create_keycloak_user(
        cls,
        user: KeycloakUser,
        keycloak_client: KeycloakAdmin,
        initial_password: str | None,
        cache: dict,
    ):
        data: dict = {
            "username": user.email,
            "email": user.email,
            "firstName": user.first_name,
            "lastName": user.last_name,
            "enabled": True,
        }

        # Look up by email (not username) because imported KC users may have a
        # different username (e.g. customernumber).
        keycloak_id = cls.get_keycloak_id_by_email(keycloak_client, user.email)
        if keycloak_id is not None:
            user.keycloak_id = keycloak_id
            keycloak_client.update_user(user_id=user.keycloak_id, payload=data)
            return

        if initial_password:
            data["credentials"] = [{"value": initial_password, "type": "password"}]
            data["emailVerified"] = True
        else:
            data["requiredActions"] = ["VERIFY_EMAIL", "UPDATE_PASSWORD"]

        if user.is_superuser:
            data["groups"] = ["superuser"]
        else:
            data["groups"] = []

        try:
            user.keycloak_id = keycloak_client.create_user(data)
        except KeycloakPostError as e:
            # Race / duplicate: another process created a user with the same
            # email between our lookup and create. Re-fetch by email and reuse.
            if e.response_code == 409:
                keycloak_id = cls.get_keycloak_id_by_email(keycloak_client, user.email)
                if keycloak_id is not None:
                    user.keycloak_id = keycloak_id
                    keycloak_client.update_user(user_id=user.keycloak_id, payload=data)
                    return
            raise

        if user.email.endswith("@example.com"):
            return

        try:
            user.send_verify_email(cache=cache)
        except Exception as e:
            print(
                "Failed to send verify email to new user: ",
                e,
                f" (email: '{user.email}', id: '{user.id}', keycloak_id: '{user.keycloak_id}'): ",
            )

        SocialAccount.objects.create(
            user=user, provider="keycloak", uid=user.keycloak_id
        )

    @classmethod
    def update_keycloak_user(
        cls,
        user: KeycloakUser,
        keycloak_client: KeycloakAdmin,
        old_first_name: str,
        old_last_name: str,
        old_email: str,
        new_first_name: str,
        new_last_name: str,
        new_email: str,
        cache: dict,
    ):
        if old_first_name != new_first_name or old_last_name != new_last_name:
            data = {"firstName": user.first_name, "lastName": user.last_name}
            keycloak_client.update_user(user_id=user.keycloak_id, payload=data)

        if old_email == new_email:
            return

        if user.email_verified(cache=cache):
            from tapir.accounts.services.mail_change_service import (
                MailChangeService,
            )

            MailChangeService.start_email_change_process(
                user=user, new_email=new_email, orig_email=old_email
            )
            return

        # in this case, don't start the email change process, just send the keycloak email to the new address and resend the link
        keycloak_client.update_user(
            user_id=user.keycloak_id, payload={"email": new_email}
        )
        user.send_verify_email(cache=cache)

    @classmethod
    def get_keycloak_client(cls, cache: dict):
        def compute():
            config = settings.KEYCLOAK_ADMIN_CONFIG

            keycloak_connection = KeycloakOpenIDConnection(
                server_url=config["SERVER_URL"],
                realm_name=config["REALM_NAME"],
                client_id=config["CLIENT_ID"],
                client_secret_key=config["CLIENT_SECRET_KEY"],
                verify=True,
            )

            return KeycloakAdmin(connection=keycloak_connection)

        return get_from_cache_or_compute(
            cache=cache, key="keycloak_client", compute_function=compute
        )

    @classmethod
    def get_user_roles(cls, keycloak_id):
        keycloak_client = KeycloakUserManager.get_keycloak_client(cache={})

        raw_roles = keycloak_client.get_composite_realm_roles_of_user(
            keycloak_id,
        )

        return [
            raw_role["name"]
            for raw_role in raw_roles
            if raw_role["name"] not in settings.KEYCLOAK_NON_TAPIR_ROLES
        ]
