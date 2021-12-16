import express from "express"
import rateLimit from "express-rate-limit"
import MongoStore from "rate-limit-mongo"
import fetch from "node-fetch"
import { createRequire } from "module"
const require = createRequire(import.meta.url)
const config = require("./token.json")
import { CronJob } from "cron"

const app = express()

app.set('trust proxy', 1)

const limiter = rateLimit({
    store: new MongoStore({
        uri: `mongodb://${config.mongoDB.ip}/${config.mongoDB.database}`,
        user: config.mongoDB.user,
        password: config.mongoDB.password,
        expireTimeMs: 60 * 60 * 1000,
    }),
    windowMs: 15 * 60 * 1000,
    max: 1,
    message: ""An Invite has already been generated for you. You can join once with that invite. \nThe link is only available for 10 minutes. You can try again in 2 hours.",
})
app.use(limiter)

async function inviter() {
    try {
        return await fetch(`https://discord.com/api/v8/channels/${config.discord.ChannelID}/invites`, {
            method: 'post',
            body: JSON.stringify({
                "max_age": 600,
                "max_uses": 1,
                "unique": true
            }),
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bot ${config.discord.token}`
            }
        }).then(async data => {
            let header = await data.headers.raw()
            let body = await data.json()

            return {
                header: header,
                body: body
            }
        })
    } catch (error) {
        console.error(error)
        return undefined
    }
}

let rateValid = 25000
let rateHour = 1000
let rateSec = 45

function timerRate(left) {
    setTimeout(() => rateValid = 25000, left * 1000)
}

app.get("/", async (req, res) => {
    if (rateHour === 0 || rateSec === 0 || rateValid === 0) return res.status(429).send("Infelizmente não posso gerar mais links por agora, volte daqui a 1 hora!!")
    rateHour -= 1
    rateSec -= 1
    const invite = await inviter()
    if (invite === undefined) return res.status(500).send("Infelizmente não consegui gerar 1 link por agora, volte daqui a 1 hora!!")
    rateValid = parseInt(invite.header['x-ratelimit-remaining'][0])
    if (rateValid === 0) timerRate(parseFloat(invite.header['x-ratelimit-reset-after'][0]))
    res.redirect(`https://discord.gg/${invite.body.code}`)
})

app.use(function (req, res) {
    res.status(404).redirect("/");
})

const rH = new CronJob('0 0 * * * *', function () {
    rateHour = 1000
}, null)
const rS = new CronJob('0 0 * * * *', function () {
    rateSec = 45
}, null)

app.listen(3001, () => {
    console.log("Ready to generate invite!")
    rH.start()
    rS.start()
})
