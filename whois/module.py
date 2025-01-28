from typing import List, Optional

import discord
from discord import app_commands
from discord.ext import commands

from pie import check, i18n, logger, utils
from pie.acl.database import ACLevelMappping
from pie.bot import Strawberry

from ..verify.database import VerifyMember

_ = i18n.Translator("modules/mgmt").translate
guild_log = logger.Guild.logger()


class Whois(commands.Cog):
    def __init__(self, bot: Strawberry):
        self.bot = bot

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @app_commands.default_permissions(administrator=True)
    @app_commands.command(name="roleinfo", description="Display role information.")
    @app_commands.describe(role="Role to investigate.")
    async def roleinfo(self, itx: discord.Interaction, role: discord.Role):
        acl_mapping = ACLevelMappping.get(itx.guild.id, role.id)

        embed = utils.discord.create_embed(
            author=itx.user,
            title=role.name,
            description=role.id,
        )
        embed.add_field(
            name=_(itx, "Member count"),
            value=f"{len(role.members)}",
        )
        embed.add_field(
            name=_(itx, "Taggable"),
            value=_(itx, "Yes") if role.mentionable else _(itx, "No"),
        )
        if acl_mapping is not None:
            embed.add_field(
                name=_(itx, "Mapping to ACLevel"),
                value=acl_mapping.level.name,
                inline=False,
            )
        await itx.response.send_message(embed=embed)

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @app_commands.default_permissions(administrator=True)
    @app_commands.command(
        name="channelinfo", description="Display channel information."
    )
    @app_commands.describe(channel="Channel to investigate.")
    async def channelinfo(self, itx: discord.Interaction, channel: discord.TextChannel):
        if itx.user not in channel.members:
            await itx.response.send_message(
                _(
                    itx,
                    "You don't have permission to view information about this channel.",
                )
            )
            return

        webhook_count = len(await channel.webhooks())
        role_count: int = 0
        user_count: int = 0
        for overwrite in channel.overwrites:
            if isinstance(overwrite, discord.Role):
                role_count += 1
            else:
                user_count += 1

        topic: str = f"{channel.topic}\n" if channel.topic else ""
        embed = utils.discord.create_embed(
            author=itx.user,
            title=f"#{channel.name}",
            description=f"{topic}{channel.id}",
        )

        if role_count:
            embed.add_field(
                name=_(itx, "Role count"),
                value=f"{role_count}",
            )
        if user_count:
            embed.add_field(
                name=_(itx, "User count"),
                value=f"{user_count}",
            )
        if webhook_count:
            embed.add_field(
                name=_(itx, "Webhook count"),
                value=f"{webhook_count}",
            )
        await itx.response.send_message(embed=embed)

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @app_commands.default_permissions(administrator=True)
    @app_commands.command(name="whois", description="See database info on member.")
    @app_commands.describe(user="Member to investigate.")
    async def whois(self, itx: discord.Interaction, user: discord.User):
        db_members: List[VerifyMember]
        db_members = VerifyMember.get(guild_id=itx.guild.id, user_id=user.id)
        db_member: Optional[VerifyMember]
        db_member = db_members[0] if db_members else None

        dc_member: Optional[discord.Member] = itx.guild.get_member(user.id)

        if not db_member and dc_member is None:
            await itx.response.send_message(_(itx, "No such user."))
            return

        await self._whois_reply(itx, db_member, dc_member)
        await guild_log.info(
            itx.user, itx.channel, f"Whois lookup for {user.name} ({user.id})."
        )

    @app_commands.guild_only()
    @check.acl2(check.ACLevel.MOD)
    @app_commands.default_permissions(administrator=True)
    @app_commands.command(name="rwhois", description="See databse info on email")
    @app_commands.describe(address="Email to investigate")
    async def rwhois(self, itx: discord.Interaction, address: str):
        db_members = VerifyMember.get(guild_id=itx.guild.id, address=address)

        if not db_members:
            await itx.response.send_message(_(itx, "Member is not in a database."))
            return

        db_member = db_members[0]

        dc_member = itx.guild.get_member(db_member.user_id)

        await self._whois_reply(itx, db_member, dc_member)
        await guild_log.info(
            itx.user, itx.channel, f"Reverse whois lookup for {address}."
        )

    async def _whois_reply(
        self,
        itx: discord.Interaction,
        db_member: VerifyMember,
        dc_member: Optional[discord.Member],
    ):
        """Function that creates an embed about member and
        sends it as response to the interaction.

        :param itx: Interaction context
        :param db_member: Member info from database
        :param dc_member: Discord member
        """
        description: str
        if dc_member is not None:
            description = f"{dc_member.name} ({dc_member.id})"
        else:
            description = f"{db_member.user_id}"

        embed = utils.discord.create_embed(
            author=itx.user,
            title=_(itx, "Whois"),
            description=description,
        )

        if db_member is not None:
            embed.add_field(
                name=_(itx, "Address"),
                value=db_member.address,
                inline=False,
            )
            embed.add_field(
                name=_(itx, "Verification code"),
                value=f"`{db_member.code}`",
            )
            embed.add_field(
                name=_(itx, "Verification status"),
                value=f"{db_member.status.name}",
            )
            embed.add_field(
                name=_(itx, "Timestamp"),
                value=utils.time.format_datetime(db_member.timestamp),
                inline=False,
            )

        if dc_member is not None:
            avatar_url: str = dc_member.display_avatar.replace(size=256).url
            embed.set_thumbnail(url=avatar_url)

            dc_member_roles = list(r.name for r in dc_member.roles[::-1][:-1])
            if dc_member_roles:
                embed.add_field(
                    name=_(itx, "Roles"),
                    value=", ".join(dc_member_roles),
                )

        await itx.response.send_message(embed=embed)


async def setup(bot: Strawberry) -> None:
    await bot.add_cog(Whois(bot))
