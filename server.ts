import express, {
    type Express,
    type Request,
    type Response,
} from "express";

import { MongoClient } from "mongodb";
import "dotenv/config"
import cors from "cors"
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken"
import { PassThrough } from "node:stream";

const app = express()
const port = process.env.PORT || 5000;

app.use(cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
}))

app.use(express.json())
app.use(cookieParser())


const uri = process.env.MONGODB_URI
if (!uri) {
    throw new Error("MONGODB_URI is not defined in .env")
}

const client = new MongoClient(uri)
const db = client.db(process.env.DB_NAME)

const users = db.collection("user")
const events = db.collection("event")
const data = db.collection("data")

const SECRET = process.env.JWT_SECRET || "together-we-can-jwt-secret"

const connectDB = async () => {
    await client.connect()

    await users.createIndex({ email: 1 }, { unique: true });
    await events.createIndex({ date: 1 })
    await data.createIndex({ eventId: 1, userEmail: 1 }, { unique: true })
    await events.createIndex({ createdByEmail: 1 })

    console.log(`Database name ${db.databaseName}`)
}

const signToken = (user: any) => {
    return jwt.sign(
        {email: user.email, name: user.name, photoURL: user.photoURL || ""},
        SECRET,
        {expiresIn: "7d"}
        
    )
}

const setAuthCookie = (res: Response, token: any) => {
    res.cookie("twc_token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })
}

const usersCol = db.collection("users")

const reqireAuth = async(req: Request, res: Response, next: any) => {
    try {
        const token = req.cookies?.twc_token || (req.headers.authorization || "").replace("Bearer", "")

        if(!token) {
            return res.status(401).json({
                message: "Please login first"
            })

            const payload = jwt.verify(token, SECRET)
            const user = await usersCol.findOne({email: payload.email}, {projection: {
                password: 0
            }})

            if(!user) {
                return res.status(401).json({
                    Message: "Account not found"
                })

                req.user = user
                next()
            }
        }
    }catch {
        return res.status(401).json(
            {
            message: "Invalid or expired session. Plaease login again."
        }
        )
    }
}
app.get('/', (req: Request, res: Response) => {
    res.send('Simple CRUD Server is running')
});

app.listen(port, async() => {
    await connectDB()
        .then(() => {
            console.log(`Simple CRUD Server is running on port: ${port}`)
        })
        .catch((err) => {
            console.log(`Failedd to connected MongoDB: ${err.message}`)
        })
})