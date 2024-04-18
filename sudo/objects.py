from typing import Union

import discord

from pie import i18n, logger

_ = i18n.Translator("modules/sudo").translate

guild_log = logger.Guild.logger()


class MessageModal(discord.ui.Modal):
    def __init__(
        self,
        bot,
        title: str,
        label: str,
        edit: bool = False,
        channel: Union[discord.TextChannel, discord.Thread] = None,
        message: discord.Message = None,
    ) -> None:
        if channel is None and not edit:
            raise ValueError("Channel can't be None when edit is not True!")

        super().__init__(title=title, custom_id="message_modal", timeout=900)

        self.bot = bot
        self.title = title
        self.channel = channel
        self.message = message
        self.edit = edit
        self.message_input = discord.ui.TextInput(
            label=label,
            custom_id="content",
            style=discord.TextStyle.long,
            required=True,
            default=message.content if message else "",
            max_length=2000,
        )
        self.add_item(self.message_input)

    async def on_submit(self, inter: discord.Interaction) -> None:
        utx = i18n.TranslationContext(inter.guild.id, inter.user.id)
        if self.edit:
            await self.message.edit(
                content=self.message_input.value,
                allowed_mentions=discord.AllowedMentions(
                    everyone=True, users=True, roles=True
                ),
            )
            await inter.response.send_message(
                _(utx, "Message edited in {channel}!").format(
                    channel=self.message.channel.mention
                ),
                ephemeral=True,
            )
            await guild_log.info(
                inter.user,
                inter.channel,
                "SUDO edited message with ID {} in channel #{}".format(
                    self.message.id, self.message.channel.name
                ),
            )
            return

        message: discord.Message = await self.channel.send(
            self.message_input.value,
            allowed_mentions=discord.AllowedMentions(
                everyone=True, users=True, roles=True
            ),
        )
        await inter.response.send_message(
            _(utx, "Message sent to {channel}!").format(channel=self.channel.mention),
            ephemeral=True,
        )

        await guild_log.info(
            inter.user,
            inter.channel,
            "SUDO sent message with ID {} in channel #{}".format(
                message.id, message.channel.name
            ),
        )
