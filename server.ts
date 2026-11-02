import express, {
    type Express,
    type Request,
    type Response
} from "express";
import { SignJWT, jwtVerify, createRemoteJWKSet } from 'jose';


import { MongoClient, ObjectId } from "mongodb";
import "dotenv/config"
import cors from "cors"
import cookieParser from "cookie-parser";
import { sign } from "node:crypto";
import { create } from "node:domain";


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

const usersCol = db.collection("user")
const events = db.collection("event")
const data = db.collection("data")

const connectDB = async () => {
    await client.connect()
    await usersCol.createIndex(
        {email: 1},
        {unique: true}
    )

    await events.createIndex({date: 1})

    await data.createIndex(
        {eventId: 1, userEmail: 1},
        {unique: true}
    )

    await events.createIndex({createdByEmail: 1})

    console.log(`Database name: ${db.databaseName}`)
}

const SECRET = new TextEncoder().encode(
    process.env.JWT_SECRET || "together-we-can-jwt-secret"
)

const signToken = async (user: {
    _id: ObjectId
    email: string
    name: string
    photoURL?: string
}) => {
    return await new SignJWT({
        email: user.email,
        name: user.name,
        photoURL: user.photoURL || ""
    })
    .setProtectedHeader({alg: "HS256"})
    .setSubject(user._id.toString())
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(SECRET)


}

// opencode
const setAuthCookie = (res: Response, token: any) => {
    res.cookie("twc_token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production"
            ? "none"
            : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000
    });
};

declare global {
    namespace Express {
        interface Request {
            user?: {
                _id: ObjectId
                name: string
                email: string
                photoURL?: string
            }
        }
    }
}

const reqireAuth = async (req: Request, res: Response, next: any) => {
    try {
        const token = req.cookies?.twc_token || req.headers.authorization?.replace(/^Bearer\s+/i, "")

        if(!token) {
            return res.status(401).json({
                message: "Please login first"
            })
        }

        const {payload} = await jwtVerify(token, SECRET)

        if (typeof payload.email !== "string") {
            return res.status(401).json({
                message: "Invalid token"
            })
        }

        const user = await usersCol.findOne(
            {email: payload.email},
            {projection: {
                password: 0
            }}
        )

        if(!user) {
            return res.status(401).json({
                message: "Account not found"
            })
        }
        req.user = {
            _id: user._id,
            name: user.name,
            email: user.email,
            photoURL: user.photoURL
        }

        next()
    }catch {
        return res.status(401).json({
            message: "Invalid or expired session. Please login again"
        })
    }
}

const googleJWKS = createRemoteJWKSet(
    new URL("https://www.googleapis.com/oauth2/v3/certs")
)




app.get('/', (req: Request, res: Response) => {
    res.send('Simple CRUD Server is running')
});

app.post("/api/auth/register", async(req: Request, res: Response) => {
    try {
        const {name, email, password, photoURL} = req.body

        const existing = await usersCol.findOne({email})

        if(existing ){
            return res.status(409).json({
                message: "An account with this email already exists"
            })
        }

        const newUser = {
            name, email, photoURL: photoURL || "", provider: "email", created: new Date() 
        }

        const {insertedId} = await usersCol.insertOne(newUser)

        const user = {
            ...newUser, _id: insertedId
        }

        const token = await signToken(user)
        setAuthCookie(res, token)
        
        res.status(201).json({
            user: {
                _id: insertedId,
                name: user.name,
                email: user.email,
                photoURL: user.photoURL
            }
        })
    }catch(err) {
        console.log(err)

        res.status(500).json({
            message: "Registration"
        })
    }
})

app.post("/api/auth/login", async(req: Request, res: Response) => {
    try {
        const {email, password} = req.body

        const user = await usersCol.findOne({email})

        if(!user || !user.password) {
            return res.status(401).json({
                message: "Invalid email or password"
            })
        }

        const token = await signToken({
            _id: user._id,
            name: user.name,
            email: user.email,
            photoURL: user.photoURL
        })

        setAuthCookie(res, token)

        res.json({
            user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                photoURL: user.photoURL || ""
            }
        })
    } catch(err) {
        console.log(err)
        res.status(500).json({
            message: "Login failed"
        })
    }
})

app.post("/api/auth/google", async(req: Request, res: Response) => {
    try{
        const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID

        if(!GOOGLE_CLIENT_ID) {
            return res.status(500).json({
                message: "Google login is not configured"
            })
        }

        const {payload} = await jwtVerify(
            req.body.credential,
            googleJWKS,
            {
                issuer: [
                    "https://accounts.google.com",
                    "accounts.google.com"
                ],
                audience: GOOGLE_CLIENT_ID
            }
        )

        const email = payload.email

        if(typeof email !== "string" || payload.email_verified !== true) {
            return res.status(400).json({
                message: "Could not verify Google account"
            })
        }

        let user = await usersCol.findOne({email})

        if(!user) {
            const newUser = {
                name: typeof payload.name === "string" ? payload.name : "Google User",
                email,
                photoURL: typeof payload.picture === "string" ? payload.picture : "", 
                provider: "google",
                createdAt: new Date()


            }

            const {insertedId} = await usersCol.insertOne(newUser)

            user = {
                ...newUser,
                _id: insertedId
            }


        }
        const token = await signToken({
            _id: user._id,
            name: user.name,
            email: user.email,
            photoURL: user.photoURL
        })

        setAuthCookie(res, token)

        res.json({
            user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                photoURL: user.photoURL || ""
            }
        })
    }catch(err) {
        console.log(err)

        res.status(401).json({
            message: "Google authentication failed"
        })
    }


})

app.get("/api/auth/me", reqireAuth, (req: Request, res: Response) => {
    const {_id, name, email, photoURL} = req.user!

    res.json({
        user: {_id, name, email, photoURL}
    })
})

app.post("/api/auth/logout", (req: Request, res: Response) => {
    res.clearCookie("twc_token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax"
    })

    res.json({
        message: "Logged out"
    })
})

app.listen(port, async () => {
    await connectDB()
        .then(() => {
            console.log(`Simple CRUD Server is running on port: ${port}`)
        })
        .catch((err) => {
            console.log(`Failedd to connected MongoDB: ${err.message}`)
        })
})