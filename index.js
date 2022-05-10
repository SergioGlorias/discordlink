import { createRequire } from "module"
const require = createRequire(import.meta.url)
const config = require("./token.json")

import fastify from "fastify"
import fastifyOauth2 from "@fastify/oauth2"

const app = fastify({ logger: true })

import fetch from "node-fetch"

import { getName } from "country-list"

import { WebhookClient, MessageEmbed } from "discord.js"
const webhook = new WebhookClient({ url: config.discord.webhookUrl }, {
    restRequestTimeout: 1 * 60 * 1000
})

import fs from "fs"
import dayjs from "dayjs"

if (!fs.readdirSync("./", { withFileTypes: true }).filter(dirent => !dirent.isDirectory()).find(dirent => dirent.name === "IPcount.json")) {
    fs.writeFileSync("./IPcount.json", JSON.stringify({}))
}

async function Country(Country) {
    let response
    if (Country === "T1") {
        response = "Tor"
    } else {
        response = getName(Country)
    }

    return response
}

async function checkIPv4(ip) {
    const RegexIPv4 = /(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/gm
    const response = RegexIPv4.test(ip)
    return response
}

async function checkIPv6(ip) {
    const RegexIPv6 = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/gm
    const response = RegexIPv6.test(ip)
    return response
}

const validStates = new Set()
import crypto from "crypto"

app.register(fastifyOauth2, {
    name: "discord",
    credentials: {
        client: {
            id: config.discord.clientId,
            secret: config.discord.clientSecret
        },
        auth: fastifyOauth2.DISCORD_CONFIGURATION,
    },
    scope: ["identify", "guilds", "guilds.join"],
    startRedirectPath: "/",
    callbackUri: `https://${config.domain}/callback`,
    generateStateFunction: (request) => {
        const state = crypto.randomBytes(20).toString("hex")
        validStates.add(state)
        return state
    },
    // custom function to check the state is valid
    checkStateFunction: (returnedState, callback) => {
        if (validStates.has(returnedState)) {
            callback()
            return
        }
        callback(new Error('Invalid state'))
    }
})

app.get("/callback", async (request, reply) => {
    try {

        const oauth2 = await app.discord.getAccessTokenFromAuthorizationCodeFlow(request)

        if (oauth2.scope.includes("guilds") && oauth2.scope.includes("guilds.join") && oauth2.scope.includes("identify")) {

            const UserData = {
                IP: request.headers["CF-Connecting-IP"] || "IP not found",
                Country: request.headers["CF-IPCountry"] || "Country not found",
            }

            let IPinfo

            if (await checkIPv4(request.headers["CF-Connecting-IP"])) {
                IPinfo = await fetch(`https://api.cloudflare.com/client/v4/accounts/${config.cloudflare.accountId}/intel/ip?ipv4=${request.headers["CF-Connecting-IP"]}`, {
                    headers: {
                        "X-Auth-Key": config.cloudflare.apiKey,
                        "X-Auth-Email": config.cloudflare.email
                    }
                }).then(res => res.json())
            } else if (await checkIPv6(request.headers["CF-Connecting-IP"])) {
                IPinfo = await fetch(`https://api.cloudflare.com/client/v4/accounts/${config.cloudflare.accountId}/intel/ip?ipv6=${request.headers["CF-Connecting-IP"]}`, {
                    headers: {
                        "X-Auth-Key": config.cloudflare.apiKey,
                        "X-Auth-Email": config.cloudflare.email
                    }
                }).then(res => res.json())
            } else {
                IPinfo = "IP not found"
            }

            if (IPinfo !== "IP not found") {
                if (IPinfo.success === true) {
                    UserData.IPType = IPinfo.result.belongs_to_ref.type
                    UserData.IPDescription = IPinfo.result.belongs_to_ref.description
                    UserData.Risk = IPinfo.result.risk_types.map(risk => risk.name)
                } else {
                    UserData.IPType = "Error"
                    UserData.IPDescription = "Error"
                    UserData.Risk = "Error"
                }
            } else {
                UserData.IPType = "IP not found"
                UserData.IPDescription = "IP not found"
                UserData.Risk = "IP not found"
            }

            const user = await fetch(`https://discordapp.com/api/users/@me`, {
                headers: {
                    Authorization: `${oauth2.token_type} ${oauth2.access_token}`
                }
            }).then(res => res.json())

            if (!user.id) return reply.code(500).send("Error")

            UserData.User = user

            let userImage

            if (user.avatar) {
                if (user.avatar.startsWith("a_")) userImage = `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.gif`
                else userImage = `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
            } else {
                userImage = `https://cdn.discordapp.com/embed/avatars/${user.discriminator % 5}.png`
            }

            if (UserData.Country !== "Country not found") {
                UserData.Country = Country(UserData.Country)
            }

            if (UserData.Country === "Tor") {

                const embed = new MessageEmbed()
                    .setTitle("User Blocked for using Tor")
                    .setDescription(`${UserData.User.username}#${UserData.User.discriminator} \`${UserData.User.id}\` has been blocked for using Tor.`)
                    .setColor("#ff0000")
                    .setTimestamp()
                    .addFields([{
                        name: "IP",
                        value: UserData.IP,
                        inline: true
                    }, {
                        name: "Country",
                        value: UserData.Country,
                        inline: true
                    }, {
                        name: "IP Type",
                        value: UserData.IPType,
                        inline: true
                    }, {
                        name: "IP Description",
                        value: UserData.IPDescription,
                        inline: true
                    }, {
                        name: "Risk",
                        value: UserData.Risk === "IP not found" ? "IP not found" : UserData.Risk.join("\n"),
                        inline: true
                    }])
                    .setThumbnail(userImage)

                await webhook.send({
                    embeds: [embed]
                })

                return reply.code(401).redirect("https://http.cat/401")
            }

            const list = fs.readFileSync("./IPcount.json", "utf8")
            const listJSON = JSON.parse(list)

            if (listJSON[UserData.IP] === undefined) {
                listJSON[UserData.IP] = {
                    IP: UserData.IP,
                    LastLogin: dayjs().toISOString(),
                }
            } else if (dayjs(listJSON[UserData.IP].LastLogin).add(6, "hours").isBefore(dayjs())) {
                return reply.code(429).redirect("https://http.cat/429")
            } else {
                listJSON[UserData.IP].LastLogin = dayjs().toISOString()
            }

            fs.writeFileSync("./IPcount.json", JSON.stringify(listJSON))

            const guilds = await fetch(`https://discordapp.com/api/users/@me/guilds`, {
                headers: {
                    Authorization: `${oauth2.token_type} ${oauth2.access_token}`
                }
            }).then(res => res.json())

            if (!guilds.length) return reply.code(500).send("Error")

            if (!guilds.find(g => g.id === config.discord.guildId)) {
                await fetch(`https://discordapp.com/api/guilds/${config.discord.guildId}/members/${user.id}`, {
                    method: "PUT",
                    headers: {
                        Authorization: `Bot ${config.discord.botToken}`
                    },
                    body: JSON.stringify({
                        access_token: oauth2.access_token,
                        roles: [config.discord.roleId]
                    })
                })
            } else {
                await fetch(`https://discordapp.com/api/guilds/${config.discord.guildId}/members/${user.id}`, {
                    method: "PATCH",
                    headers: {
                        Authorization: `Bot ${config.discord.botToken}`
                    },
                    body: JSON.stringify({
                        roles: [config.discord.roleId]
                    })
                })
            }

            const embed = new MessageEmbed()
                .setTitle("User Login")
                .setDescription(`${UserData.User.username}#${UserData.User.discriminator} \`${UserData.User.id}\` has logged in.`)
                .setColor("#00ff00")
                .setTimestamp()
                .addFields([{
                    name: "IP",
                    value: UserData.IP,
                    inline: true
                }, {
                    name: "Country",
                    value: UserData.Country,
                    inline: true
                }, {
                    name: "IP Type",
                    value: UserData.IPType,
                    inline: true
                }, {
                    name: "IP Description",
                    value: UserData.IPDescription,
                    inline: true
                }, {
                    name: "Risk",
                    value: UserData.Risk === "IP not found" ? "IP not found" : UserData.Risk.join("\n"),
                    inline: true
                }])
                .setThumbnail(userImage)

            await webhook.send({
                embeds: [embed]
            })

            return reply.code(200).send("Bem vindo! :D " + UserData.User.username + "!\n Agora você está conectado no servidor.")
        }
    } catch (e) {
        console.log(e)
        return reply.code(500).send("Ocorreu um erro. Tente novamente.")
    }
})

app.setNotFoundHandler((request, reply) => {
    return reply.redirect("/")
})

app.listen(config.port, () => {
    console.log(`Server started on port ${config.port}`)
})