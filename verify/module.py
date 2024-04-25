import asyncio
import contextlib
import csv
import os
import random
import smtplib
import string
import tempfile
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional, Union

import imap_tools
import unidecode

import discord
from discord import app_commands
from discord.ext import commands

import pie.database.config
from pie import check, exceptions, i18n, logger, storage, utils
from pie.bot import Strawberry
from pie.utils.objects import ConfirmView

from .database import (
    CustomMapping,
    MappingExtension,
    VerifyMapping,
    VerifyMember,
    VerifyMessage,
    VerifyRole,
    VerifyRule,
    VerifyStatus,
)

_ = i18n.Translator("modules/mgmt").translate
bot_log = logger.Bot.logger()
guild_log = logger.Guild.logger()
config = pie.database.config.Config.get()


SMTP_SERVER: str = os.getenv("SMTP_SERVER")
IMAP_SERVER: str = os.getenv("IMAP_SERVER")
SMTP_ADDRESS: str = os.getenv("SMTP_ADDRESS")
SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD")


def test_dotenv() -> None:
    if type(SMTP_SERVER) is not str:
        raise exceptions.DotEnvException("SMTP_SERVER is not set.")
    if type(SMTP_ADDRESS) is not str:
        raise exceptions.DotEnvException("SMTP_ADDRESS is not set.")
    if type(SMTP_PASSWORD) is not str:
        raise exceptions.DotEnvException("SMTP_PASSWORD is not set.")
    if type(IMAP_SERVER) is not str:
        raise exceptions.DotEnvException("IMAP_SERVER is not set.")


test_dotenv()


MAIL_HEADER_PREFIX = "X-strawberry.py-"


class Verify(commands.Cog):
    verification: app_commands.Group = app_commands.Group(
        name="verification",
        description="Verification administration and management.",
        default_permissions=discord.Permissions(administrator=True),
    )

    verification_welcome: app_commands.Group = app_commands.Group(
        name="welcome",
        description="Verification welcome message configuration.",
        parent=verification,
    )

    verification_mapping: app_commands.Group = app_commands.Group(
        name="mapping",
        description="Verification mapping configuration.",
        parent=verification,
    )

    verification_rule: app_commands.Group = app_commands.Group(
        name="rule", description="Verification rule configuration.", parent=verification
    )

    verification_reverify: app_commands.Group = app_commands.Group(
        name="reverify", description="Reverification commands.", parent=verification
    )

    def __init__(self, bot):
        self.bot: Strawberry = bot

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.EVERYONE)
    @app_commands.command(
        name="verify", description="Send verification code to the email."
    )
    async def verify(self, itx: discord.Interaction, address: str):
        if not address:
            return

        await itx.response.defer(thinking=True, ephemeral=True)

        # Check if user is in database
        if await self._member_exists(itx, address):
            return

        # Check if address is in use
        if await self._address_exists(itx, address):
            return

        # Check if address is supported
        if not await self._is_supported_address(itx, address):
            return

        code: str = self._generate_code()

        message: MIMEMultipart = self._get_message(itx.user, itx.channel, address, code)

        email_sent = await self._send_email(itx, message)

        if not email_sent:
            return

        VerifyMember.add(
            guild_id=itx.guild.id,
            user_id=itx.user.id,
            address=address,
            code=code,
            status=VerifyStatus.PENDING,
        )

        await guild_log.info(
            itx.user,
            itx.channel,
            "Verification e-mail sent.",
        )

        await (await itx.original_response()).edit(
            content=_(
                itx,
                ("I've sent you the verification code " "to the submitted e-mail."),
            )
        )

        await self.post_verify(itx, address)

    async def post_verify(self, itx: discord.Interaction, address: str):
        """Wait some time after the user requested verification code.

        Then connect to IMAP server and check for possilibity that they used
        wrong, invalid e-mail. If such e-mails are found, they will be logged.

        :param address: User's e-mail address.
        """
        # TODO Use embeds
        await asyncio.sleep(20)
        unread_messages = self._check_inbox_for_errors()
        for message in unread_messages:
            guild: discord.Guild = self.bot.get_guild(int(message["guild"]))
            user: discord.Member = self.bot.get_user(int(message["user"]))
            channel: discord.TextChannel = guild.get_channel(int(message["channel"]))
            await guild_log.warning(
                user,
                channel,
                "Could not deliver verification code: "
                f"{message['subject']} (User ID {message['user']})",
            )

            error_private: str = _(
                itx,
                (
                    "I could not send the verification code, you've probably made "
                    "a typo: `{address}`. Invoke the command `/strip` "
                    "before requesting a new code."
                ),
            ).format(address=address)
            error_epilog: str = _(
                itx,
                (
                    "If I'm wrong and the e-mail is correct, "
                    "contact the moderator team."
                ),
            )
            if not await utils.discord.send_dm(
                itx.user,
                error_private + "\n" + error_epilog,
            ):
                error_public: str = (
                    _(
                        itx,
                        (
                            "{mention} I could not send the verification code, you've probably made "
                            "a typo. Invoke the command `/strip` "
                            "before requesting a new code."
                        ),
                    ).format(mention=itx.user.mention),
                )
                await itx.channel.send(
                    error_public + "\n" + error_epilog,
                    delete_after=60,
                )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.EVERYONE)
    @app_commands.command(
        name="submit", description="Submit verification code received by email."
    )
    async def submit(self, itx: discord.Interaction, code: str):
        if not code:
            return

        db_members = VerifyMember.get(guild_id=itx.guild.id, user_id=itx.user.id)
        if not db_members or db_members[0].code is None:
            await itx.response.send_message(
                _(itx, "You have to request the code first."), ephemeral=True
            )
            return

        db_member = db_members[0]

        if db_member.status != VerifyStatus.PENDING:
            await guild_log.info(
                itx.user,
                itx.channel,
                (
                    "Attempted to submit the code with bad status: "
                    f"`{VerifyStatus(db_member.status).name}`."
                ),
            )
            await itx.response.send_message(
                _(
                    itx,
                    (
                        "You are not in code verification phase. "
                        "Contact the moderator team."
                    ),
                ),
                ephemeral=True,
            )
            return

        fixed_code: str = self._repair_code(code)
        if db_member.code != fixed_code:
            await guild_log.info(
                itx.user,
                itx.channel,
                f"Attempted to submit bad code: `{utils.text.sanitise(code)}`.",
            )
            await itx.response.send_message(
                _(itx, "That is not your verification code."), ephemeral=True
            )
            return

        await itx.response.defer(thinking=True, ephemeral=True)

        mapping = await self._map(
            itx=itx, guild_id=itx.guild.id, email=db_member.address
        )

        if not mapping or not mapping.rule or not mapping.rule.roles:
            await (await itx.original_response()).edit(
                content=_(itx, "Could not assign roles. Please contact moderator team.")
            )
            await guild_log.error(
                itx.user,
                itx.channel,
                "Member could not be verified due to missing mapping, rule or roles. Rule name: {name}".format(
                    name=mapping.rule.name if mapping.rule else "(None)"
                ),
            )
            return

        await self._add_roles(itx.user, mapping.rule.roles)

        config_message = mapping.rule.message

        db_member.status = VerifyStatus.VERIFIED
        db_member.save()

        await guild_log.info(itx.user, itx.channel, "Verification successfull.")

        if not config_message:
            config_message = VerifyMessage.get_default(itx.guild.id)
        if not config_message:
            await utils.discord.send_dm(
                itx.author,
                _(itx, "You have been verified, congratulations!"),
            )
        else:
            await utils.discord.send_dm(itx.user, config_message.message)

        with contextlib.suppress(Exception):
            (await itx.original_response()).delete()

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.EVERYONE)
    @app_commands.command(
        name="strip",
        description="Remove all roles and reset verification status to None.",
    )
    async def strip(self, itx: discord.Interaction):
        db_members = VerifyMember.get(guild_id=itx.guild.id, user_id=itx.user.id)

        db_member = db_members[0] if db_members else None

        if db_member and db_member.status.value < VerifyStatus.NONE.value:
            await guild_log.info(
                itx.user,
                itx.channel,
                f"Strip attempt blocked, has status {VerifyStatus(db_member.status)}.",
            )
            await itx.response.send_message(
                _(itx, "Something went wrong, contact the moderator team."),
                ephemeral=True,
            )
            return

        dialog = utils.discord.create_embed(
            author=itx.user,
            title=_(itx, "Strip"),
            description=_(
                itx,
                (
                    "By clicking the confirm button you will have all your roles removed "
                    "and your verification will be revoked. "
                    "You will be able to perform new verification afterwards."
                ),
            ),
        )
        view = ConfirmView(utx=itx, embed=dialog, ephemeral=True, delete=False)
        view.timeout = 90
        answer = await view.send()
        if answer is not True:
            await (await itx.original_response()).edit(
                content=_(itx, "Stripping aborted."), embed=None
            )
            return

        roles = [role for role in itx.user.roles if role.is_assignable()]

        with contextlib.suppress(discord.Forbidden):
            await itx.user.remove_roles(*roles, reason="strip")

        message: str = "Stripped"
        if db_member:
            db_member.delete()
            message += " and removed from database"
        message += "."
        await guild_log.info(itx.user, itx.channel, message)

        await utils.discord.send_dm(
            itx.user,
            _(
                itx,
                (
                    "You've been deleted from the database "
                    "and your roles have been removed. "
                    "You have to go through verfication in order to get back."
                ),
            ),
        )

    @check.acl2(check.ACLevel.MOD)
    @verification.command(
        name="anonymize",
        description="When anonymize is True, bot log won't contain email addresses.",
    )
    async def verification_anonymize(self, itx: discord.Interaction, anonymize: bool):
        storage.set(
            module=self, guild_id=itx.guild.id, key="anonymize", value=anonymize
        )
        if anonymize:
            await itx.response.send_message(
                _(itx, "Anonymization is **ON**. Emails won't appear in logs.")
            )
        else:
            await itx.response.send_message(
                _(itx, "Anonymization is **OFF**. Emails will appear in logs.")
            )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.SUBMOD)
    @verification.command(
        name="groupstrip",
        description="Remove roles from the users and set's verify status to None. User is not notified about this.",
    )
    async def verification_groupstrip(
        self, itx: discord.Interaction, member: discord.Member
    ):
        dialog = utils.discord.create_embed(
            author=itx.user,
            title=_(itx, "Group strip"),
            description=_(
                itx,
                (
                    "**{member}** will lose all their roles and their "
                    "verification will be revoked. They will not be notified about this. "
                    "Do you want to continue?"
                ),
            ).format(member=member.name),
        )
        view = ConfirmView(utx=itx, embed=dialog, ephemeral=True, delete=False)
        view.timeout = 90
        answer = await view.send()
        if answer is not True:
            try:
                await (await itx.original_response()).edit(_(itx, "Stripping aborted."))
                return
            except Exception:
                pass
            return

        try:
            await view.message.delete()
        except Exception:
            pass

        itx: discord.Interaction = view.itx

        await itx.response.defer(thinking=True, ephemeral=True)

        db_members = VerifyMember.get(guild_id=itx.guild.id, user_id=member.id)
        if db_members:
            db_member = db_members[0]
            db_member.delete()

        if len(getattr(member, "roles", [])) > 1:
            roles = [role for role in member.roles if role.is_assignable()]
            with contextlib.suppress(discord.Forbidden):
                await member.remove_roles(*roles, reason="groupstrip")

        await (await itx.original_response()).edit(
            content=_(
                itx,
                "Member **{member}** ({member_id}) stripped.",
            ).format(member=member.name, member_id=member.id)
        )
        await guild_log.warning(
            itx.user,
            itx.channel,
            "User {member} ({member_id}) removed from database and group stripped.".format(
                member=member.name, member_id=member.id
            ),
        )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification.command(name="grouprolestrip")
    async def verification_grouprolestrip(
        self, itx: discord.Interaction, role: discord.Role
    ):
        """Remove all roles and reset verification status to None
        from all the users that have given role. Users are not notified
        about this.
        """

        dialog = utils.discord.create_embed(
            author=itx.user,
            title=_(itx, "Role based strip"),
            description=_(
                itx,
                (
                    "**{count}** members with role **{role}** will lose all their roles "
                    "and their verification will be revoked. They will not be notified "
                    "about this. Do you want to continue?"
                ),
            ).format(role=role.name, count=len(role.members)),
        )
        view = ConfirmView(utx=itx, embed=dialog, ephemeral=True, delete=False)
        view.timeout = 90
        answer = await view.send()
        if answer is not True:
            try:
                await (await itx.original_response()).edit(_(itx, "Stripping aborted."))
            except Exception:
                pass
            return

        removed_db: int = 0
        removed_dc: int = 0

        itx = view.itx

        await itx.response.defer(thinking=True, ephemeral=True)

        for member in role.members:
            db_members = VerifyMember.get(guild_id=itx.guild.id, user_id=member.id)
            if db_members:
                db_member = db_members[0]
                db_member.delete()
                removed_db += 1
            if len(getattr(member, "roles", [])) > 1:
                roles = [r for r in member.roles if r.is_assignable()]
                with contextlib.suppress(discord.Forbidden):
                    await member.remove_roles(*roles, reason="grouprolestrip")
                removed_dc += 1

        await (await view.itx.original_response()).edit(
            _(
                itx,
                (
                    "**{db}** database entries have been removed, "
                    "**{dc}** users have been stripped."
                ),
            ).format(db=removed_db, dc=removed_dc)
        )
        await guild_log.warning(
            itx.user,
            itx.channel,
            f"Removed {removed_db} database entries and "
            f"stripped {removed_dc} members with group role strip on {role.name}.",
        )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification_welcome.command(
        name="set",
        description="Set post verification message for your guild or a rule.",
    )
    @app_commands.describe(rule_name="Name of the rule. Use `0` for guild.")
    async def verification_welcome_set(
        self, itx: discord.Interaction, rule_name: str, text: str
    ):
        if not text:
            return
        if rule_name != 0:
            rule = VerifyRule.get(guild_id=itx.guild.id, name=rule_name)
            if not rule:
                await itx.response.send_message(
                    _(itx, "Rule named {name} was not found!").format(name=rule_name),
                    ephemeral=True,
                )
                return
            rule = rule[0]
        else:
            rule = None
        VerifyMessage.set(itx.guild.id, text, rule)
        await itx.response.send_message(
            _(
                itx,
                "Message has been set for rule {rule}.",
            ).format(rule=_(itx, "(Guild)") if rule_name == "0" else rule_name),
            ephemeral=True,
        )
        await guild_log.info(
            itx.user,
            itx.channel,
            "Welcome message changed for rule {}.".format(
                "(Guild)" if rule_name == "0" else rule_name
            ),
        )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification_welcome.command(
        name="unset",
        description="Unset post verification message for your guild or a rule.",
    )
    @app_commands.describe(rule_name="Name of the rule. Use `0` for guild.")
    async def verification_welcomemessage_unset(
        self, itx: discord.Interaction, rule_name: str
    ):
        if rule_name != "0":
            rule = VerifyRule.get(guild_id=itx.guild.id, name=rule_name)
            if rule:
                message = rule[0].message
            else:
                await itx.response.send_message(
                    _(itx, "Rule named {name} was not found!").format(name=rule_name)
                )
                return
        else:
            message = VerifyMessage.get_default(itx.guild.id)

        if message:
            message.delete()

        await itx.response.send_message(
            _(itx, "Welcome message has been set to default for rule {rule}.").format(
                rule=_(itx, "(Guild)") if rule_name == "0" else rule_name
            )
        )
        await guild_log.info(
            itx.user,
            itx.channel,
            "Welcome message set to default for rule {}.".format(
                "(Guild)" if rule_name == "0" else rule_name
            ),
        )

    @check.acl2(check.ACLevel.SUBMOD)
    @verification_welcome.command(
        name="list", description="Show post verificationmessages."
    )
    async def verification_welcomemessage_list(self, itx: discord.Interaction):
        class Item:
            def __init__(self, message: VerifyMessage = None):
                self.rule = message.rule.name if message and message.rule else None
                self.message = message.message if message else None

        default_message = Item()
        default_message.rule = _(itx, "Server default")
        default_message.message = getattr(
            VerifyMessage.get_default(itx.guild.id),
            "message",
            _(itx, "You have been verified, congratulations!"),
        )
        messages = [default_message]
        configured_messages = [
            Item(message) for message in VerifyMessage.get_all(itx.guild.id)
        ]
        configured_messages = filter(
            lambda x: True if x.rule and x.message is not None else False,
            configured_messages,
        )
        messages.extend(configured_messages)

        table: List[str] = utils.text.create_table(
            messages,
            header={
                "rule": _(itx, "Rule name"),
                "message": _(itx, "Message to send"),
            },
        )

        page = table[0]
        await itx.response.send_message(page)
        if len(table) > 1:
            for page in table[1:]:
                await itx.followup.send("```" + page + "```")

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification.command(
        name="update", description="Update the user's verification status."
    )
    async def verification_update(
        self, itx: discord.Interaction, member: discord.Member, status: VerifyStatus
    ):
        verify_member = VerifyMember.get(itx.guild.id, user_id=member.id)

        if not verify_member:
            await itx.response.send_message(
                _(itx, "That member is not in the database."), ephemeral=True
            )
            return

        verify_member[0].status = status
        verify_member[0].save()

        await guild_log.info(
            itx.user,
            itx.channel,
            "Verification status of {member} changed to {status}.".format(
                member=member.name, status=status
            ),
        )
        await itx.response.send_message(
            _(
                itx,
                "Member verification status of **{member}** has been updated to **{status}**.",
            ).format(
                member=member.mention,
                status=status,
            ),
            ephemeral=True,
        )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification_mapping.command(
        name="info", description="Get mapping information by username and domain."
    )
    @app_commands.describe(
        email="Use `@domain.tld` for domain default or `@` for guild deafult.",
        hide_response="Hide response from other users.",
    )
    async def verification_mapping_info(
        self, itx: discord.Interaction, email: str, hide_response: bool = True
    ):
        if "@" not in email or len(email.split("@")) != 2:
            await itx.response.send_message(
                _(itx, "Email must contain exactly 1 @ character."), ephemeral=True
            )
            return

        parts = email.split("@")
        username = parts[0]
        domain = parts[1]

        mapping = await self._map(
            itx=itx, guild_id=itx.guild.id, username=username, domain=domain
        )

        if not username and not domain:
            title = _(itx, "Default mapping")
            mapping_name = _(itx, "Default")
        else:
            title = _(itx, "Mapping for {username}@{domain}").format(
                username=username, domain=domain
            )
            mapping_name = mapping.username + "@" + mapping.domain

        embed = utils.discord.create_embed(author=itx.user, title=title)

        if isinstance(mapping, CustomMapping):
            embed.add_field(
                name=_(itx, "Mapping extension:"),
                value=MappingExtension.get_name(mapping),
            )

        embed.add_field(name=_(itx, "Applied mapping:"), value=mapping_name)

        embed.add_field(
            name=_(itx, "Verification allowed:"),
            value=_(itx, "True") if mapping and mapping.rule else _(itx, "False"),
        )

        embed.add_field(
            name=_(itx, "Rule name:"),
            value=mapping.rule.name if mapping and mapping.rule else "-",
        )

        await itx.response.send_message(embed=embed, ephemeral=hide_response)

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @commands.max_concurrency(1, per=commands.BucketType.default, wait=False)
    @verification_mapping.command(name="import", description="Import mapping data.")
    @app_commands.describe(
        attachment="CSV file in format: `username;domain;rule_name`. For domain / global rule, leave the part empty.",
        wipe="Remove all mapping data and do clean import.",
    )
    async def verification_mapping_import(
        self,
        itx: discord.Interaction,
        attachment: discord.Attachment,
        wipe: bool = False,
    ):
        if not attachment.filename.lower().endswith("csv"):
            await itx.response.send_message(
                _(itx, "Supported format is only CSV."), ephemeral=True
            )
            return
        await itx.response.send_message(
            _(itx, "Processing. Make a coffee, it may take a while.")
        )

        if wipe:
            async with itx.channel.typing():
                wiped = VerifyMapping.wipe(itx.guild.id)
                await itx.followup.send(
                    _(itx, "Wiped {wiped} mappings.").format(wiped=wiped)
                )

        async with itx.channel.typing():
            data_file = tempfile.NamedTemporaryFile()
            await attachment.save(data_file.name)
            file = open(data_file.name, "rt")

            csv_reader = csv.reader(file, delimiter=";")

            count = 0

            for row in csv_reader:
                count += 1
                if len(row) != 3:
                    await itx.followup.send(
                        _(itx, "Row {row} has invalid number of columns!").format(
                            row=count
                        )
                    )
                    continue

                username, domain, rule_name = row
                rule = None

                if len(rule_name):
                    rule = VerifyRule.get(guild_id=itx.guild.id, name=rule_name)
                    if not rule:
                        await itx.followup.send(
                            _(itx, "Row {row} has invalid rule name: {name}!").format(
                                row=count, name=rule_name
                            )
                        )
                        continue
                    rule = rule[0]

                VerifyMapping.add(
                    guild_id=itx.guild.id,
                    username=username,
                    domain=domain,
                    rule=rule,
                )
                # To keep the bot alive and responding
                asyncio.sleep(0)

        file.close()
        data_file.close()

        await itx.followup.send(
            _(itx, "Imported {count} mappings.").format(count=count)
        )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification_mapping.command(
        name="remove", description="Remove verification mapping."
    )
    @app_commands.describe(
        email="Use `@domain.tld` for domain default or `@` for guild deafult."
    )
    async def verification_mapping_remove(self, itx: discord.Interaction, email: str):
        if "@" not in email or len(email.split("@")) != 2:
            await itx.response.send_message(
                _(itx, "Email must contain exactly 1 @ character."), ephemeral=True
            )
            return

        parts = email.split("@")
        username = parts[0]
        domain = parts[1]

        mapping = VerifyMapping.get(
            guild_id=itx.guild.id, username=username, domain=domain
        )

        if not mapping:
            await itx.response.send_message(
                _(itx, "Mapping for {name}@{domain} not found!").format(
                    name=username, domain=domain
                )
            )
            return

        dialog = utils.discord.create_embed(
            author=itx.user,
            title=_(itx, "Mapping remove"),
            description=_(
                itx, "Do you really want to remove mapping for {name}@{domain}?"
            ).format(
                name=username,
                domain=domain,
            ),
        )
        view = ConfirmView(utx=itx, embed=dialog, ephemeral=True, delete=False)
        view.timeout = 90
        answer = await view.send()
        if answer is not True:
            try:
                await (await itx.original_response()).edit(_(itx, "Removing aborted."))
            except Exception:
                pass
            return

        mapping[0].delete()
        await view.itx.response.send_message(_(itx, "Mapping successfuly removed."))

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification_rule.command(name="add", description="Creates verification rule.")
    @app_commands.describe(name="Name of the rule.", role="First role to add.")
    async def verification_rule_add(
        self, itx: discord.Interaction, name: str, role: discord.Role = None
    ):
        rule = VerifyRule.add(guild_id=itx.guild.id, name=name)

        if not rule:
            await itx.response.send_message(
                _(itx, "Rule with name {name} already exists!").format(name=name),
                ephemeral=True,
            )
            return

        if role:
            rule.add_roles(role.id)

        await itx.response.send_message(
            _(itx, "Rule with name {name} added!").format(name=name)
        )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification_rule.command(name="remove", description="Delete verification rule")
    @app_commands.describe(name="Name of the rule.")
    async def verification_rule_remove(self, itx: discord.Interaction, name: str):
        rule = VerifyRule.get(guild_id=itx.guild.id, name=name)

        if not rule:
            await itx.response.send_message(
                _(itx, "Rule with name {name} not found!").format(name=name)
            )
            return

        dialog = utils.discord.create_embed(
            author=itx.user,
            title=_(itx, "Rule remove"),
            description=_(itx, "Do you really want to remove rule {name}?").format(
                name=name
            ),
        )
        view = ConfirmView(utx=itx, embed=dialog, ephemeral=True, delete=False)
        view.timeout = 90
        answer = await view.send()
        if answer is not True:
            try:
                await (await itx.original_response()).edit(_(itx, "Removing aborted."))
            except Exception:
                pass
            return

        rule[0].delete()

        await view.itx.response.send_message(
            _(itx, "Rule {name} successfuly removed.").format(name=name)
        )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification_rule.command(name="list", description="List all rules.")
    async def verification_rule_list(self, itx: discord.Interaction):
        rules = VerifyRule.get(guild_id=itx.guild.id)

        class Item:
            def __init__(self, rule):
                self.rule = rule.name
                self.role_count = len(rule.roles)

        items = []

        for rule in rules:
            items.append(Item(rule))

        tables: List[str] = utils.text.create_table(
            items,
            header={
                "rule": _(itx, "Rule name"),
                "role_count": _(itx, "Role count"),
            },
        )

        await itx.response.defer()

        for page in tables:
            await itx.followup.send("```" + page + "```")

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification_rule.command(name="info", description="Show information about rule.")
    async def verification_rule_info(self, itx: discord.Interaction, rule_name: str):
        rule = VerifyRule.get(guild_id=itx.guild.id, name=rule_name)

        if not rule:
            await itx.response.send_message(
                _(itx, "Rule with name {name} not found!").format(name=rule_name)
            )
            return

        rule = rule[0]

        embed = utils.discord.create_embed(
            author=itx.user,
            title=_(itx, "Rule information"),
            description=rule.name,
        )

        embed.add_field(
            name=_(itx, "Has custom message:"),
            value=_(itx, "True") if rule.message else _(itx, "False"),
        )

        roles = []

        for db_role in rule.roles:
            role = itx.guild.get_role(db_role.role_id)
            if role:
                roles.append(role.mention)
            else:
                roles.append(f"{db_role.role_id} (DELETED)")

        embed.add_field(
            name=_(itx, "Assigned roles:"),
            value=", ".join(roles) if roles else "-",
            inline=False,
        )
        await itx.response.send_message(embed=embed, ephemeral=True)

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification_rule.command(
        name="addrole", description="Add Discord roles to verification rule."
    )
    @app_commands.describe(rule_name="Name of the rule.", role="Discord role to add.")
    async def verification_rule_addrole(
        self, itx: discord.Interaction, rule_name: str, role: discord.Role
    ):
        rule = VerifyRule.get(guild_id=itx.guild.id, name=rule_name)

        if not rule:
            await itx.response.send_message(
                _(itx, "Rule with name {name} not found!").format(name=rule_name),
                ephemeral=True,
            )
            return

        rule[0].add_roles(role.id)

        await itx.response.send_message(
            _(itx, "Role {role} added to rule {name}!").format(
                role=role.name, name=rule_name
            )
        )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification_rule.command(
        name="removerole", description="Remove Discord roles from verification rule."
    )
    @app_commands.describe(
        rule_name="Name of the rule.", role="Discord role to remove."
    )
    async def verification_rule_removeroles(
        self, itx: discord.Interaction, rule_name: str, role: discord.Role
    ):
        rule = VerifyRule.get(guild_id=itx.guild.id, name=rule_name)

        if not rule:
            await itx.response.send_message(
                _(itx, "Rule with name {name} not found!").format(name=rule_name)
            )
            return

        rule[0].delete_roles(role.id)

        await itx.response.send_message(
            _(itx, "Role {role} removed from rule {name}!").format(
                role=role.name, name=rule_name
            )
        )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @verification_reverify.command(
        name="preview", description="Show changes that would be made by reverification."
    )
    async def verification_reverify_preview(self, itx: discord.Interaction):
        text = _(
            itx,
            (
                "Do you really want to preview reverify results? "
                "This operation might take a while and the bot might hit rate limit!"
            ),
        )

        dialog = utils.discord.create_embed(
            author=itx.user, title=_(itx, "Reverify confirm"), description=text
        )
        view = ConfirmView(utx=itx, embed=dialog, delete=False)
        view.timeout = 90
        confirm = await view.send()
        if not confirm:
            await (await itx.original_response()).edit(
                content=_(itx, "Reverify preview aborted.")
            )
            return

        await self._process_reverify(itx, preview=True)

    @check.acl2(check.ACLevel.MOD)
    @verification_reverify.command(
        name="execute", description="THIS COMMAND IS IRREVERSIBLE!"
    )
    async def verification_reverify_execute(self, itx: discord.Interaction):
        text = _(
            itx,
            (
                "Do you really want to execute reverify? "
                "The operation is **irreversible**."
                "This operation might take a while and the bot might hit rate limit!"
            ),
        )

        dialog = utils.discord.create_embed(
            author=itx.user, title=_(itx, "Reverify confirm"), description=text
        )
        view = ConfirmView(utx=itx, embed=dialog, delete=False)
        view.timeout = 90
        confirm = await view.send()
        if not confirm:
            await (await itx.original_response()).edit(
                content=_(itx, "Reverify preview aborted.")
            )
            return

        await self._process_reverify(itx, preview=False)

    async def _process_reverify(self, itx: discord.Interaction, preview: bool = True):
        """Helper function to process the reverify.

        In preview mode, this function only sends messages to chat instead of updating users.

        :param itx: Discord interaction
        :param preview: If True, no changes to users, roles and DB are made.
        """
        managed_roles: List[int] = list(
            set([db_role.role_id for db_role in VerifyRole.get(itx.guild.id)])
        )

        if not await self._check_managed_roles(itx, managed_roles):
            return

        await itx.response.send_message(_(itx, "Reverification starting..."))

        verify_members: List[VerifyMember] = VerifyMember.get(guild_id=itx.guild.id)

        stripped_count = 0
        updated_count = 0

        for verify_member in verify_members:
            dc_member: discord.Member = itx.guild.get_member(verify_member.user_id)

            if not dc_member:
                continue

            dc_member_roles: List[int] = [role.id for role in dc_member.roles]

            member_managed_roles: List[int] = [
                role for role in managed_roles if role in dc_member_roles
            ]

            mapping = await self._map(
                itx=itx, guild_id=itx.guild.id, email=verify_member.address
            )

            # Mapping or rule not found = strip
            if not mapping or not mapping.rule:
                stripped_count += 1
                if preview:
                    await itx.followup.send(
                        _(
                            itx,
                            "[Preview] Member {member} stripped - no mapping found or verification blocked!",
                        ).format(member=dc_member.mention)
                    )
                else:
                    roles = [role for role in dc_member.roles if role.is_assignable()]
                    with contextlib.suppress(discord.Forbidden):
                        await dc_member.remove_roles(*roles, reason="Reverify strip")
                    verify_member.delete()
                continue

            mapped_roles = [role.role_id for role in mapping.rule.roles]
            add_roles = [
                role for role in mapped_roles if role not in member_managed_roles
            ]
            remove_roles = [
                role for role in member_managed_roles if role not in mapped_roles
            ]

            if not add_roles and not remove_roles:
                continue

            updated_count += 1

            if preview:
                await self._preview_update(itx, add_roles, remove_roles, dc_member)
            else:
                add_roles = [itx.guild.get_role(role) for role in add_roles]
                await dc_member.add_roles(*add_roles, reason="reverify")

                remove_roles = [itx.guild.get_role(role) for role in remove_roles]
                await dc_member.remove_roles(*remove_roles, reason="reverify")

        await itx.followup.send(
            _(
                itx,
                "Updated {updated} and stripped {stripped} out of {total} verify members.",
            ).format(
                updated=str(updated_count),
                stripped=str(stripped_count),
                total=str(len(verify_members)),
            )
        )

    async def _check_managed_roles(
        self, itx: discord.Interaction, managed_roles: List[int]
    ) -> bool:
        """Helper function to check if every managed role exists.

        :param itx: Command context
        :param managed_roles: List of managed role IDs
        :return: True if everything is OK, False if role does not exist
        """
        for managed_role in managed_roles:
            role = itx.guild.get_role(managed_role)
            if not role:
                await itx.response.send_message(
                    _(
                        itx,
                        "Role with ID {role_id} was not found! Please fix your verify rules and try again!",
                    ).format(role_id=managed_role)
                )
                return False
        return True

    async def _preview_update(
        self,
        itx: discord.Interaction,
        add_roles: List[int],
        remove_roles: List[int],
        dc_member: discord.Member,
    ):
        """Helper function to format the reverify preview message.

        :param itx: Command context
        :param add_roles: List of role IDs to add
        :param remove_roles: List of role IDs to remove
        :param dc_member: Member that would be affected by reverify
        """
        removed_roles = (
            ", ".join(["<@&{role}>".format(role=role) for role in remove_roles])
            if remove_roles
            else "-"
        )
        added_roles = (
            ", ".join(["<@&{role}>".format(role=role) for role in add_roles])
            if add_roles
            else "-"
        )
        await itx.followup.send(
            _(
                itx,
                "[Preview] Removed roles {removed_roles} and added roles {added_roles} for {member}.",
            ).format(
                removed_roles=removed_roles,
                added_roles=added_roles,
                member=dc_member.mention,
            )
        )

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        """Add the roles back if they have been verified before."""
        db_members = VerifyMember.get(guild_id=member.guild.id, user_id=member.id)
        if not db_members:
            return

        db_member = db_members[0]

        if db_member.status != VerifyStatus.VERIFIED.value:
            return

        mapping = await self._map(guild_id=member.guild.id, email=db_member.address)

        if not mapping or not mapping.rule or not mapping.rule.roles:
            await guild_log.error(
                member,
                None,
                "Can't skip verification - mapping, rule or roles missing. Rule name: {name}".format(
                    name=mapping.rule.name if mapping.rule else "(None)"
                ),
            )
            return

        await self._add_roles(member, mapping.rule.roles)

        # We need a channel to log the event in the guild log channel.
        # We are just picking the first one.
        await guild_log.info(
            member,
            None,
            "New member already in database, skipping verification.",
        )

    @commands.Cog.listener()
    async def on_member_ban(self, guild, member: Union[discord.Member, discord.User]):
        """When the member is banned, update the database status."""
        db_members = VerifyMember.get(guild_id=guild.id, user_id=member.id)

        if db_members:
            db_member = db_members[0]
            db_member.status = VerifyStatus.BANNED
            db_member.save()
            await guild_log.info(
                member,
                member.guild.text_channels[0],
                "Member has been banned, database status updated.",
            )
            return

        VerifyMember.add(
            guild_id=guild.id,
            user_id=member.id,
            address=None,
            code=None,
            status=VerifyStatus.BANNED,
        )
        await guild_log.info(
            member,
            member.guild.text_channels[0],
            "Member has been banned, adding to database.",
        )

    #

    # TODO Loop to check the inbox for error e-mails

    #

    async def _member_exists(self, itx: discord.Interaction, address: str):
        """Check if VerifyMember exists in database.

        If the member exists, the event is logged and a response is
        sent to the user.

        :param itx: Command context
        :param address: Supplied e-mail address
        """
        db_member: VerifyMember = VerifyMember.get(
            guild_id=itx.guild.id, user_id=itx.user.id
        )
        if db_member:
            await guild_log.debug(
                itx.user,
                itx.channel,
                (
                    "Attempted to verify with Discord account already in database (status: {status})."
                ).format(status=VerifyStatus(db_member[0].status).name),
            )
            await (await itx.original_response()).edit(
                content=_(
                    itx,
                    (
                        "Your user account is already in the database. "
                        "Check the e-mail inbox or contact the moderator team."
                    ),
                )
            )
            return True

        return False

    async def _address_exists(self, itx: discord.Interaction, address: str):
        """Check if member's e-mail exists in database.

        If the e-mail exists, the event is logged and a response is
        sent to the user.

        :param itx: Command context
        :param address: Supplied e-mail address
        """
        db_members = VerifyMember.get(guild_id=itx.guild.id, address=address)
        if db_members:
            db_member = db_members[0]
            dc_member: Optional[discord.User] = self.bot.get_user(db_member.user_id)
            dc_member_str: str = (
                f"'{utils.text.sanitise(dc_member.name)}' ({db_member.user_id})"
                if dc_member is not None
                else f"ID '{db_member.user_id}'"
            )
            await guild_log.info(
                itx.user,
                itx.channel,
                (
                    "Attempted to verify with address associated with different user: "
                    f"The address is registered to account {dc_member_str} "
                    f"with status '{VerifyStatus(db_member.status).name}'."
                ),
            )

            await (await itx.original_response()).edit(
                content=_(
                    itx,
                    (
                        "This e-mail is already in the database "
                        "registered under different user account. "
                        "Login with that account and/or contact the moderator team."
                    ),
                )
            )
            return True

        return False

    async def _is_supported_address(self, itx: discord.Interaction, address: str):
        """Check if the address is allowed to verify.

        If the address is not supported, the event is logged and a response is
        sent to the user.

        :param itx: Command context
        :param address: Supplied e-mail address
        """
        try:
            mapping = await self._map(itx=itx, guild_id=itx.guild.id, email=address)
        except ValueError:
            mapping = None

        if not mapping or not mapping.rule:
            anonymize: bool = storage.get(
                module=self, guild_id=itx.guild.id, key="anonymize", default_value=True
            )
            await guild_log.info(
                itx.user,
                itx.channel,
                "Attempted to verify with unsupported address {address}.".format(
                    address=address if not anonymize else "(anonymized)"
                ),
            )
            await (await itx.original_response()).edit(
                content=_(itx, "This e-mail cannot be used.")
            )
            return False

        return True

    async def _map(
        self,
        guild_id: int,
        itx: discord.Interaction = None,
        username: str = None,
        domain: str = None,
        email: str = None,
    ) -> Union[CustomMapping, VerifyMapping]:
        extension: MappingExtension
        for name, extension in MappingExtension._extensions.items():
            try:
                mapping: CustomMapping = await extension.map(
                    guild_id=guild_id, username=username, domain=domain, email=email
                )
            except Exception as exc:
                await bot_log.error(
                    itx.user if itx else None,
                    itx.channel if itx else None,
                    f"Error during '{name}' MappingExtension processing.",
                    exception=exc,
                )
            if mapping:
                if not isinstance(mapping, CustomMapping):
                    await bot_log.error(
                        itx.user if itx else None,
                        itx.channel if itx else None,
                        f"MappingExtension '{name}' map function returned {mapping.__class__}.",
                    )
                return mapping

        return VerifyMapping.map(
            guild_id=guild_id, username=username, domain=domain, email=email
        )

    def _generate_code(self):
        """Generate verification code."""
        letters: str = string.ascii_uppercase.replace("O", "").replace("I", "")
        code: str = "".join(random.choices(letters + string.digits, k=8))
        return code

    def _repair_code(self, code: str):
        """Repair user-submitted code.

        Return the uppercase version. Disallow capital ``i`` and ``o`` as they
        may be similar to ``1`` and ``0``.
        """
        return code.upper().replace("I", "1").replace("O", "0")

    def _get_message(
        self,
        member: discord.Member,
        channel: discord.TextChannel,
        address: str,
        code: str,
    ) -> MIMEMultipart:
        """Generate the verification e-mail."""
        BOT_URL = "https://github.com/strawberry-py"

        utx = i18n.TranslationContext(member.guild.id, member.id)

        clear_list: List[str] = [
            _(
                utx,
                "Your verification code for Discord server {guild_name} is {code}.",
            ).format(guild_name=member.guild.name, code=code),
            _(utx, "You can use it by sending the following message:"),
            "  "
            + _(utx, "/submit {code}").format(code=code),
            _(utx, "to the channel named #{channel}. Do not copy the command as it might not work.").format(channel=channel.name),
        ]
        clear: str = "\n".join(clear_list)

        message = MIMEMultipart("alternative")

        # TODO Instead of normalization to ASCII we should do encoding
        # so the accents are kept.
        # '=?utf-8?b?<base64 with plus instead of equals>?=' should work,
        # but it needs more testing.
        ascii_bot_name: str = unidecode.unidecode(self.bot.user.name)
        ascii_member_name: str = unidecode.unidecode(member.name)
        ascii_guild_name: str = unidecode.unidecode(member.guild.name)

        message["Subject"] = f"{ascii_guild_name} → {ascii_member_name}"
        message["From"] = f"{ascii_bot_name} <{SMTP_ADDRESS}>"
        message["To"] = f"{ascii_member_name} <{address}>"
        message["Bcc"] = f"{ascii_bot_name} <{SMTP_ADDRESS}>"

        message[MAIL_HEADER_PREFIX + "user"] = f"{member.id}"
        message[MAIL_HEADER_PREFIX + "bot"] = f"{self.bot.user.id}"
        message[MAIL_HEADER_PREFIX + "channel"] = f"{channel.id}"
        message[MAIL_HEADER_PREFIX + "guild"] = f"{member.guild.id}"
        message[MAIL_HEADER_PREFIX + "url"] = BOT_URL

        message.attach(MIMEText(clear, "plain"))

        return message

    async def _send_email(
        self, itx: discord.Interaction, message: MIMEMultipart, retry: bool = True
    ) -> None:
        """Send the verification e-mail."""
        try:
            with smtplib.SMTP_SSL(SMTP_SERVER) as server:
                server.ehlo()
                server.login(SMTP_ADDRESS, SMTP_PASSWORD)
                server.send_message(message)
                return True
        except (smtplib.SMTPException, smtplib.SMTPNotSupportedError) as exc:
            if retry and not isinstance(exc, smtplib.SMTPNotSupportedError):
                await bot_log.warning(
                    itx.user,
                    itx.user,
                    "Could not send verification e-mail, trying again.",
                    exception=exc,
                )
                return await self._send_email(itx, message, False)
            else:
                await bot_log.error(
                    itx.user,
                    itx.channel,
                    "Could not send verification e-mail.",
                    "Email: {}".format(
                        message["To"].encode("unicode-escape").decode("utf-8")
                    ),
                    exception=exc,
                )
                await (await itx.original_response()).edit(
                    content=_(
                        itx,
                        (
                            "An error has occured while sending the code. "
                            "Contact the moderator team."
                        ),
                    )
                )
                return False

    async def _add_roles(self, member: discord.Member, db_roles: List[VerifyRole]):
        """Add roles to the member."""

        roles: List[discord.Role] = list()
        for db_role in db_roles:
            role = member.guild.get_role(db_role.role_id)
            if role:
                roles.append(role)
            else:
                await guild_log.error(
                    member,
                    None,
                    "Role with ID {id} could not be found! Rule: {name}.".format(
                        id=db_role.role_id, name=db_role.rule.name
                    ),
                )
        await member.add_roles(*roles)

    def _check_inbox_for_errors(self):
        """Connect to the IMAP server and fetch unread e-mails.

        If the message contains verification headers, it will be returned as
        dictionary containing those headers.
        """
        unread_messages = []

        with imap_tools.MailBox(IMAP_SERVER).login(
            SMTP_ADDRESS, SMTP_PASSWORD
        ) as mailbox:
            messages = [
                m
                for m in mailbox.fetch(
                    imap_tools.AND(seen=False),
                    mark_seen=False,
                )
            ]
            mark_as_read: List = []

            for m in messages:
                has_delivery_status: bool = False

                for part in m.obj.walk():
                    if part.get_content_type() == "message/delivery-status":
                        has_delivery_status = True
                        break

                if not has_delivery_status:
                    continue

                rfc_message = m.obj.as_string()
                info: dict = {}

                for line in rfc_message.split("\n"):
                    if line.startswith(MAIL_HEADER_PREFIX):
                        key, value = line.split(":", 1)
                        info[key.replace(MAIL_HEADER_PREFIX, "")] = value.strip()
                if not info:
                    continue

                mark_as_read.append(m)
                info["subject"] = m.subject
                unread_messages.append(info)

            mailbox.flag(
                [m.uid for m in mark_as_read],
                (imap_tools.MailMessageFlags.SEEN,),
                True,
            )

        return unread_messages


async def setup(bot) -> None:
    await bot.add_cog(Verify(bot))
