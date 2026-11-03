
import express, {
    type Request,
    type Response
} from "express";

import {SignJWT, jwtVerify, createRemoteJWKSet} from "jose"

import { MongoClient, ObjectId } from "mongodb"
import "dotenv/config"
import cors from "cors"
import cookieParser from "cookie-parser"

const app = express()
const port = process.env.PORT || 5000


// MIDDLEWARE
app.use(cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    credentials: true
}))

app.use(express.json())
app.use(cookieParser())


// DATABASE
const uri = process.env.MONGODB_URI

if (!uri) {
    throw new Error("MONGODB_URI is not defined in .env")
}

const client = new MongoClient(uri)
const db = client.db(process.env.DB_NAME)

const usersCol = db.collection("user")
const events = db.collection("event")
const data = db.collection("data")

const commentsCol = db.collection("comments")
const savesCol = db.collection("saves")
const waitlistCol = db.collection("waitlist")


// DATABASE CONNECTION
const connectDB = async () => {
    await client.connect()

    await usersCol.createIndex(
        { email: 1 },
        { unique: true }
    )

    await events.createIndex({ date: 1 })
    await events.createIndex({ createdByEmail: 1 })

    await data.createIndex(
        { eventId: 1, userEmail: 1 },
        { unique: true }
    );

    await commentsCol.createIndex({ eventId: 1 })

    await savesCol.createIndex(
        { eventId: 1, userEmail: 1 },
        { unique: true }
    );

    await waitlistCol.createIndex(
        { eventId: 1, userEmail: 1 },
        { unique: true }
    );

    await waitlistCol.createIndex({
        eventId: 1,
        joinedAt: 1
    });

    console.log(`Database name: ${db.databaseName}`)
};


// JWT
const SECRET = new TextEncoder().encode(
    process.env.JWT_SECRET || "together-we-can-jwt-secret"
);


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
        .setProtectedHeader({ alg: "HS256" })
        .setSubject(user._id.toString())
        .setIssuedAt()
        .setExpirationTime("7d")
        .sign(SECRET)
};


// AUTH COOKIE
const setAuthCookie = (res: Response, token: string) => {
    res.cookie("twc_token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production"
            ? "none"
            : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })
}


// USER TYPE
declare global {
    namespace Express {
        interface Request {
            user?: {
                _id: ObjectId
                name: string
                email: string
                photoURL?: string
            };
        }
    }
}


// AUTH MIDDLEWARE
const reqireAuth = async (req: Request, res: Response, next: any) => {
    try {
        const token =
            req.cookies?.twc_token ||
            req.headers.authorization?.replace(/^Bearer\s+/i, "");

        if (!token) {
            return res.status(401).json({
                message: "Please login first"
            })
        }

        const { payload } = await jwtVerify(token, SECRET)

        if (typeof payload.email !== "string") {
            return res.status(401).json({
                message: "Invalid token"
            })
        }

        const user = await usersCol.findOne(
            { email: payload.email },
            {
                projection: {
                    password: 0
                }
            }
        )

        if (!user) {
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

    } catch {
        return res.status(401).json({
            message: "Invalid or expired session. Please login again"
        })
    }
};


// OPTIONAL AUTH
const optionalAuth = async (
    req: Request, res: Response, next: any) => {
    try {
        const token =
            req.cookies?.twc_token ||
            req.headers.authorization?.replace(/^Bearer\s+/i, "");

        if (!token) {
            return next()
        }

        const { payload } = await jwtVerify(token, SECRET)

        if (typeof payload.email !== "string") {
            return next();
        }

        const user = await usersCol.findOne(
            { email: payload.email },
            {
                projection: {
                    password: 0
                }
            }
        )

        if (user) {
            req.user = {
                _id: user._id,
                name: user.name,
                email: user.email,
                photoURL: user.photoURL
            };
        }

        next()

    } catch {
        next()
    }
};


// GOOGLE JWKS
const googleJWKS = createRemoteJWKSet(
    new URL("https://www.googleapis.com/oauth2/v3/certs")
);


// EVENT RESPONSE HELPER
const formatEvent = async (
    event: any, email?: string) => {
    let isJoined = false
    let isSaved = false

    if (email) {
        isJoined = (event.joinedBy || []).includes(email);

        const saved = await savesCol.findOne({
            eventId: event._id.toString(),
            userEmail: email
        });

        isSaved = Boolean(saved)
    }

    return {
        ...event,
        _id: event._id.toString(),
        isJoined,
        isSaved
    };
};


const formatEvents = async (
    eventList: any[],
    email?: string
) => {
    return await Promise.all(
        eventList.map(event => formatEvent(event, email))
    )
}


// HOME
app.get("/", (req: Request, res: Response) => {
    res.send("Simple CRUD Server is running")
})


// REGISTER
app.post(
    "/api/auth/register",
    async (req: Request, res: Response) => {
        try {
            const { name, email, password, photoURL } = req.body

            if (!name || !email || !password) {
                return res.status(400).json({
                    message: "Name, email and password are required"
                })
            }

            const existing = await usersCol.findOne({ email })

            if (existing) {
                return res.status(409).json({
                    message: "An account with this email already exists"
                })
            }

            const newUser = {
                name,
                email,
                password,
                photoURL: photoURL || "",
                provider: "email",
                createdAt: new Date()
            }

            const { insertedId } = await usersCol.insertOne(newUser);

            const user = {
                ...newUser,
                _id: insertedId
            }

            const token = await signToken(user);

            setAuthCookie(res, token);

            res.status(201).json({
                user: {
                    _id: insertedId,
                    name: user.name,
                    email: user.email,
                    photoURL: user.photoURL
                }
            })

        } catch (err) {
            console.log(err);

            res.status(500).json({
                message: "Registration failed"
            })
        }
    }
);


// LOGIN
app.post(
    "/api/auth/login",
    async (req: Request, res: Response) => {
        try {
            const { email, password } = req.body

            const user = await usersCol.findOne({ email })

            if (!user || !user.password || user.password !== password) {
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

        } catch (err) {
            console.log(err)

            res.status(500).json({
                message: "Login failed"
            })
        }
    }
);


// GOOGLE LOGIN
app.post(
    "/api/auth/google",
    async (req: Request, res: Response) => {
        try {
            const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

            if (!GOOGLE_CLIENT_ID) {
                return res.status(500).json({
                    message: "Google login is not configured"
                })
            }

            const credential = req.body.credential;

            if (typeof credential !== "string") {
                return res.status(400).json({
                    message: "Google credential is required"
                })
            }

            const { payload } = await jwtVerify(
                credential,
                googleJWKS,
                {
                    issuer: [
                        "https://accounts.google.com",
                        "accounts.google.com"
                    ],
                    audience: GOOGLE_CLIENT_ID
                }
            )

            const email = payload.email;

            if (
                typeof email !== "string" ||
                payload.email_verified !== true
            ) {
                return res.status(400).json({
                    message: "Could not verify Google account"
                })
            }

            let user = await usersCol.findOne({ email });

            if (!user) {
                const newUser = {
                    name: typeof payload.name === "string"
                        ? payload.name
                        : "Google User",

                    email,

                    photoURL: typeof payload.picture === "string"
                        ? payload.picture
                        : "",

                    provider: "google",
                    createdAt: new Date()
                };

                const { insertedId } = await usersCol.insertOne(newUser);

                user = {
                    ...newUser,
                    _id: insertedId
                };
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

        } catch (err) {
            console.log(err);

            res.status(401).json({
                message: "Google authentication failed"
            });
        }
    }
);


// CURRENT USER
app.get(
    "/api/auth/me",
    reqireAuth,
    (req: Request, res: Response) => {
        const { _id, name, email, photoURL } = req.user!;

        res.json({
            user: {
                _id,
                name,
                email,
                photoURL
            }
        });
    }
);


// LOGOUT
app.post(
    "/api/auth/logout",
    (req: Request, res: Response) => {
        res.clearCookie("twc_token", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production"
                ? "none"
                : "lax"
        });

        res.json({
            message: "Logged out"
        });
    }
);


// GET ALL UPCOMING EVENTS
app.get(
    "/api/events",
    optionalAuth,
    async (req: Request, res: Response) => {
        try {
            const eventList = await events
                .find(
                    { date: { $gte: new Date() } },
                    { projection: { description: 0 } }
                )
                .sort({ date: 1 })
                .toArray();

            res.json({
                events: await formatEvents(
                    eventList,
                    req.user?.email
                )
            });

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// GET RECENT 6 EVENTS
app.get(
    "/api/events/recent",
    optionalAuth,
    async (req: Request, res: Response) => {
        try {
            const eventList = await events
                .find(
                    { date: { $gte: new Date() } },
                    { projection: { description: 0 } }
                )
                .sort({ date: 1 })
                .limit(6)
                .toArray();

            res.json({
                events: await formatEvents(
                    eventList,
                    req.user?.email
                )
            });

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            });
        }
    }
);


// GET MY EVENTS
app.get(
    "/api/events/mine",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            const eventList = await events
                .find({
                    createdByEmail: req.user!.email
                })
                .sort({ date: 1 })
                .toArray()

            res.json({
                events: await formatEvents(
                    eventList,
                    req.user!.email
                )
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            });
        }
    }
);


// GET EVENT ATTENDEES
app.get(
    "/api/events/:id/attendees",
    async (req: Request, res: Response) => {
        try {
            if (!ObjectId.isValid(String(req.params.id))) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            const event = await events.findOne(
                { _id: new ObjectId(String(req.params.id)) },
                { projection: { joinedBy: 1 } }
            )

            if (!event) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            const emails = event.joinedBy || []

            if (!emails.length) {
                return res.json({ attendees: [] })
            }

            const [users, joins] = await Promise.all([
                usersCol.find(
                    { email: { $in: emails } },
                    {
                        projection: {
                            name: 1,
                            email: 1,
                            photoURL: 1,
                            _id: 0
                        }
                    }
                ).toArray(),

                data.find({
                    eventId: req.params.id,
                    userEmail: { $in: emails }
                }).toArray()
            ]);

            const attendees = emails
                .map((email: string) => {
                    const user = users.find(
                        item => item.email === email
                    )

                    if (!user) return null;

                    const join = joins.find(
                        item => item.userEmail === email
                    )

                    return {
                        email,
                        name: user.name,
                        photoURL: user.photoURL || "",
                        joinedAt: join?.joinedAt || null
                    }
                })
                .filter(Boolean)

            res.json({ attendees })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// GET EVENT COMMENTS
app.get(
    "/api/events/:id/comments",
    async (req: Request, res: Response) => {
        try {
            if (!ObjectId.isValid(String(req.params.id))) {
                return res.status(404).json({
                    message: "Event not found"
                });
            }

            const event = await events.findOne({
                _id: new ObjectId(String(req.params.id))
            });

            if (!event) {
                return res.status(404).json({
                    message: "Event not found"
                });
            }

            const comments = await commentsCol
                .find({ eventId: req.params.id })
                .sort({ createdAt: -1 })
                .limit(100)
                .toArray();

            res.json({ comments });

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            });
        }
    }
);


// GET SINGLE EVENT
app.get(
    "/api/events/:id",
    optionalAuth,
    async (req: Request, res: Response) => {
        try {
            if (!ObjectId.isValid(String(req.params.id))) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            const event = await events.findOne({
                _id: new ObjectId(String(req.params.id))
            })

            if (!event) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            res.json({
                event: await formatEvent(
                    event,
                    req.user?.email
                )
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
);

// CREATE EVENT
app.post(
    "/api/events",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            const {
                title,
                description,
                date,
                capacity
            } = req.body;

            if (
                !title ||
                !date ||
                isNaN(new Date(date).getTime())
            ) {
                return res.status(400).json({
                    message: "Title and valid date are required"
                })
            }

            const doc = {
                ...req.body,
                capacity: capacity ?? null,
                date: new Date(date),

                createdByEmail: req.user!.email,

                createdBy: {
                    name: req.user!.name,
                    email: req.user!.email
                },

                joinedBy: [],
                createdAt: new Date()
            }

            const { insertedId } = await events.insertOne(doc);

            res.status(201).json({
                event: await formatEvent(
                    { ...doc, _id: insertedId },
                    req.user!.email
                )
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// POST COMMENT
app.post(
    "/api/events/:id/comments",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            if (!ObjectId.isValid(String(req.params.id))) {
                return res.status(404).json({
                    message: "Event not found"
                });
            }

            const event = await events.findOne({
                _id: new ObjectId(String(req.params.id))
            })

            if (!event) {
                return res.status(404).json({
                    message: "Event not found"
                });
            }

            const { body } = req.body;

            if (!body || typeof body !== "string") {
                return res.status(400).json({
                    message: "Comment is required"
                });
            }

            const comment = {
                eventId: req.params.id,
                userEmail: req.user!.email,
                authorName: req.user!.name,
                authorPhoto: req.user!.photoURL || "",
                body,
                createdAt: new Date()
            }

            const { insertedId } = await commentsCol.insertOne(comment);

            res.status(201).json({
                comment: {
                    ...comment,
                    _id: insertedId
                }
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// JOIN EVENT
app.post(
    "/api/events/:id/join",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            if (!ObjectId.isValid(String(req.params.id))) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            const event = await events.findOne({
                _id: new ObjectId(String(req.params.id))
            })

            if (!event) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            if (event.date < new Date()) {
                return res.status(400).json({
                    message: "This event has already ended"
                })
            }

            const joinedBy = event.joinedBy || [];
            const email = req.user!.email;

            if (joinedBy.includes(email)) {
                return res.status(409).json({
                    message: "You have already joined this event"
                })
            }

            const capacity = event.capacity ?? null;

            if (capacity && joinedBy.length >= capacity) {
                return res.status(409).json({
                    message: "This event is full. Join the waitlist.",
                    full: true
                })
            }

            const filter: any = {
                _id: new ObjectId(String(req.params.id)),
                joinedBy: { $ne: email }
            }

            if (capacity) {
                filter.$expr = {
                    $lt: [
                        {
                            $size: {
                                $ifNull: ["$joinedBy", []]
                            }
                        },
                        capacity
                    ]
                }
            }

            const result = await events.updateOne(
                filter,
                {
                    $addToSet: {
                        joinedBy: email
                    }
                }
            )

            if (result.modifiedCount === 0) {
                return res.status(409).json({
                    message: "This event is full or you already joined",
                    full: true
                })
            }

            await data.updateOne(
                {
                    eventId: req.params.id,
                    userEmail: email
                },
                {
                    $set: {
                        eventId: req.params.id,
                        userEmail: email,
                        joinedAt: new Date(),
                        promotedAt: null
                    }
                },
                { upsert: true }
            )

            await waitlistCol.deleteOne({
                eventId: req.params.id,
                userEmail: email
            })

            res.status(201).json({
                message: "Joined the event successfully"
            })
        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// JOIN WAITLIST
app.post(
    "/api/events/:id/waitlist",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            if (!ObjectId.isValid(String(req.params.id))) {
                return res.status(404).json({
                    message: "Event not found"
                });
            }

            const event = await events.findOne({
                _id: new ObjectId(String(req.params.id))
            });

            if (!event) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            if (event.date < new Date()) {
                return res.status(400).json({
                    message: "This event has already ended"
                })
            }

            const email = req.user!.email
            const joinedBy = event.joinedBy || []
            const capacity = event.capacity ?? null

            if (joinedBy.includes(email)) {
                return res.status(409).json({
                    message: "You have already joined this event"
                })
            }

            if (!capacity || joinedBy.length < capacity) {
                return res.status(400).json({
                    message: "Spots are available. Join the event instead."
                })
            }

            await waitlistCol.updateOne(
                {
                    eventId: req.params.id,
                    userEmail: email
                },
                {
                    $setOnInsert: {
                        eventId: req.params.id,
                        userEmail: email,
                        joinedAt: new Date()
                    }
                },
                { upsert: true }
            )

            const waitlistCount = await waitlistCol.countDocuments({
                eventId: req.params.id
            })

            res.status(201).json({
                message: "You are on the waitlist.",
                waitlistCount
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// SAVE EVENT
app.post(
    "/api/events/:id/save",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            if (!ObjectId.isValid(String(req.params.id))) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            const event = await events.findOne({
                _id: new ObjectId(String(req.params.id))
            })

            if (!event) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            await savesCol.updateOne(
                {
                    eventId: req.params.id,
                    userEmail: req.user!.email
                },
                {
                    $setOnInsert: {
                        eventId: req.params.id,
                        userEmail: req.user!.email,
                        createdAt: new Date()
                    }
                },
                { upsert: true }
            )

            res.json({ saved: true })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// UPDATE OWN EVENT
app.put(
    "/api/events/:id",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            if (!ObjectId.isValid(String(req.params.id))) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            const event = await events.findOne({
                _id: new ObjectId(String(req.params.id)),
                createdByEmail: req.user!.email
            })

            if (!event) {
                return res.status(404).json({
                    message: "Event not found or you don't have permission"
                })
            }

            const { title, date, capacity } = req.body;

            if (
                !title ||
                !date ||
                isNaN(new Date(date).getTime())
            ) {
                return res.status(400).json({
                    message: "Title and valid date are required"
                });
            }

            const joinedCount = event.joinedBy?.length || 0;

            if (capacity && joinedCount > capacity) {
                return res.status(400).json({
                    message: `Capacity cannot be lower than ${joinedCount}`
                })
            }

            await events.updateOne(
                {
                    _id: new ObjectId(String(req.params.id)),
                    createdByEmail: req.user!.email
                },
                {
                    $set: {
                        ...req.body,
                        capacity: capacity ?? null,
                        date: new Date(date)
                    }
                }
            )

            res.json({
                message: "Event updated successfully"
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// DELETE OWN EVENT
app.delete(
    "/api/events/:id",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            if (!ObjectId.isValid(String(req.params.id))) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            const result = await events.deleteOne({
                _id: new ObjectId(String(req.params.id)),
                createdByEmail: req.user!.email
            })

            if (result.deletedCount === 0) {
                return res.status(404).json({
                    message: "Event not found or you don't have permission"
                })
            }

            await Promise.all([
                data.deleteMany({
                    eventId: req.params.id
                }),

                savesCol.deleteMany({
                    eventId: req.params.id
                }),

                waitlistCol.deleteMany({
                    eventId: req.params.id
                }),

                commentsCol.deleteMany({
                    eventId: req.params.id
                })
            ])

            res.json({
                message: "Event deleted successfully"
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// LEAVE EVENT + PROMOTE WAITLIST USER

app.delete(
    "/api/events/:id/join",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            if (!ObjectId.isValid(String(req.params.id))) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            const event = await events.findOne({
                _id: new ObjectId(String(req.params.id))
            })

            if (!event) {
                return res.status(404).json({
                    message: "Event not found"
                })
            }

            const email = req.user!.email

            if (!event.joinedBy?.includes(email)) {
                return res.status(400).json({
                    message: "You have not joined this event"
                })
            }

            const eventId = new ObjectId(String(req.params.id))
            const userEmail = req.user!.email

            await events.updateOne(
                { _id: eventId },
                {
                    $pull: {
                        joinedBy: userEmail as never
                    }
                }
            )

            await data.deleteOne({
                eventId: req.params.id,
                userEmail: email
            })

            let promoted = false;

            const nextUsers = await waitlistCol
                .find({ eventId: req.params.id })
                .sort({ joinedAt: 1 })
                .limit(1)
                .toArray()

            const nextUser = nextUsers[0]

            if (nextUser) {
                await waitlistCol.deleteOne({
                    eventId: req.params.id,
                    userEmail: nextUser.userEmail
                })

                const added = await events.updateOne(
                    {
                        _id: new ObjectId(String(req.params.id)),
                        joinedBy: { $ne: nextUser.userEmail }
                    },
                    {
                        $addToSet: {
                            joinedBy: nextUser.userEmail
                        }
                    }
                )

                if (added.modifiedCount > 0) {
                    await data.updateOne(
                        {
                            eventId: req.params.id,
                            userEmail: nextUser.userEmail
                        },
                        {
                            $set: {
                                eventId: req.params.id,
                                userEmail: nextUser.userEmail,
                                joinedAt: new Date(),
                                promotedAt: new Date()
                            }
                        },
                        { upsert: true }
                    )

                    promoted = true;
                }
            }

            res.json({
                message: "You have left the event",
                promoted
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// LEAVE WAITLIST
app.delete(
    "/api/events/:id/waitlist",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            await waitlistCol.deleteOne({
                eventId: req.params.id,
                userEmail: req.user!.email
            })

            res.json({
                message: "You have left the waitlist"
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// UNSAVE EVENT
app.delete(
    "/api/events/:id/save",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            await savesCol.deleteOne({
                eventId: req.params.id,
                userEmail: req.user!.email
            })

            res.json({
                saved: false
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// USER BADGE CATALOG
type UserCounts = {
    joined: number
    hosted: number
    volunteersReached: number
    saved: number
    comments: number
    communities: number
    waitlisted: number
}

const badgeCatalog: {
    id: string;
    label: string;
    description: string;
    check: (counts: UserCounts) => boolean;
}[] = [
    {
        id: "first-step",
        label: "First Step",
        description: "Joined your first event",
        check: ({ joined }) => joined >= 1
    },
    {
        id: "regular",
        label: "Regular",
        description: "Joined 3 community events",
        check: ({ joined }) => joined >= 3
    },
    {
        id: "changemaker",
        label: "Changemaker",
        description: "Joined 5 community events",
        check: ({ joined }) => joined >= 5
    },
    {
        id: "host",
        label: "Host",
        description: "Created your first event",
        check: ({ hosted }) => hosted >= 1
    },
    {
        id: "builder",
        label: "Community Builder",
        description: "Hosted 3 events",
        check: ({ hosted }) => hosted >= 3
    },
    {
        id: "crowd-puller",
        label: "Crowd Puller",
        description: "Reached 10 volunteers across your events",
        check: ({ volunteersReached }) => volunteersReached >= 10
    },
    {
        id: "curator",
        label: "Curator",
        description: "Saved 3 events for later",
        check: ({ saved }) => saved >= 3
    },
    {
        id: "voice",
        label: "Community Voice",
        description: "Shared 3 messages in event discussions",
        check: ({ comments }) => comments >= 3
    }
]


// GET USER STATS
app.get("/api/users/stats",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            const email = req.user!.email;
            const now = new Date()

            const [
                hostedEvents,
                joinedEvents,
                saved,
                comments,
                recentPromotions
            ] = await Promise.all([
                events.find({
                    createdByEmail: email
                }).toArray(),

                events.find({
                    joinedBy: email
                }).toArray(),

                savesCol.countDocuments({
                    userEmail: email
                }),

                commentsCol.countDocuments({
                    userEmail: email
                }),

                data
                    .find({
                        userEmail: email,
                        promotedAt: { $ne: null }
                    })
                    .sort({ promotedAt: -1 })
                    .limit(5)
                    .toArray()
            ])

            const volunteersReached = hostedEvents.reduce(
                (total, event) => {
                    return total + (event.joinedBy?.length || 0);
                },
                0
            )

            const communities = new Set(
                [...hostedEvents, ...joinedEvents].map(
                    event => event.location
                )
            ).size

            const counts: UserCounts = {
                hosted: hostedEvents.length,
                joined: joinedEvents.length,
                saved,
                comments,
                volunteersReached,
                communities,
                waitlisted: await waitlistCol.countDocuments({
                    userEmail: email
                })
            }

            const badges = badgeCatalog.map(
                ({ check, ...badge }) => ({
                    ...badge,
                    earned: check(counts)
                })
            )

            const promotionIds = recentPromotions
                .map(join => String(join.eventId))
                .filter(id => ObjectId.isValid(id))
                .map(id => new ObjectId(id))

            const promotionEvents = promotionIds.length
                ? await events
                    .find(
                        {
                            _id: { $in: promotionIds },
                            date: { $gte: now }
                        },
                        {
                            projection: {
                                title: 1,
                                date: 1,
                                location: 1,
                                thumbnail: 1,
                                eventType: 1
                            }
                        }
                    )
                    .toArray()
                : []

            const eventMap = new Map(
                promotionEvents.map(event => [
                    String(event._id),
                    event
                ])
            )

            const promotions: {
                event: any;
                promotedAt: Date;
            }[] = []

            for (const join of recentPromotions) {
                const event = eventMap.get(String(join.eventId));

                if (event) {
                    promotions.push({
                        event,
                        promotedAt: join.promotedAt
                    })
                }
            }

            res.json({
                stats: {
                    ...counts,
                    badges
                },
                promotions
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)


// UPDATE OWN PROFILE
app.put("/api/users/profile",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            const { name, photoURL } = req.body;

            if (
                typeof name !== "string" ||
                !name.trim() ||
                (
                    photoURL !== undefined &&
                    typeof photoURL !== "string"
                )
            ) {
                return res.status(400).json({
                    message: "Valid name and photoURL are required"
                })
            }

            await usersCol.updateOne(
                { email: req.user!.email },
                {
                    $set: {
                        name: name.trim(),
                        photoURL: photoURL || ""
                    }
                }
            )

            const updated = await usersCol.findOne(
                { email: req.user!.email },
                {
                    projection: {
                        password: 0
                    }
                }
            )

            res.json({
                user: updated
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)

// GET PUBLIC COMMUNITY STATS
app.get(
    "/api/stats",
    async (req: Request, res: Response) => {
        try {
            const now = new Date();

            const weekFromNow = new Date(
                now.getTime() + 7 * 24 * 60 * 60 * 1000
            );

            const [
                eventsCount,
                thisWeek,
                volunteerEmails,
                joins,
                locations
            ] = await Promise.all([
                events.countDocuments({
                    date: { $gte: now }
                }),

                events.countDocuments({
                    date: {
                        $gte: now,
                        $lte: weekFromNow
                    }
                }),

                data.distinct("userEmail"),

                data.countDocuments({}),

                events.distinct("location", {
                    date: { $gte: now }
                })
            ]);

            res.json({
                stats: {
                    events: eventsCount,
                    thisWeek,
                    volunteers: volunteerEmails.length,
                    joins,
                    communities: locations.length
                }
            });

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            });
        }
    }
);

// GET MY SAVED UPCOMING EVENTS
app.get("/api/saves/my",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            const saves = await savesCol
                .find({ userEmail: req.user!.email })
                .sort({ createdAt: -1 })
                .toArray();

            const ids = saves
                .map((save) => {
                    const id = String(save.eventId);

                    return ObjectId.isValid(id)
                        ? new ObjectId(id)
                        : null;
                })
                .filter((id): id is ObjectId => id !== null);

            if (!ids.length) {
                return res.json({ events: [] });
            }
            const savedEvents = await events
                .find({
                    _id: { $in: ids },
                    date: { $gte: new Date() }
                })
                .sort({ date: 1 })
                .toArray();

            res.json({
                events: formatEvents(savedEvents, req.user!.email)
            });

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            });
        }
    }
)


// GET /api/saves/my — saved upcoming events for logged-in user
app.get(
    "/api/saves/my",
    reqireAuth,
    async (req: Request, res: Response) => {
        try {
            const saves = await savesCol
                .find({ userEmail: req.user!.email })
                .sort({ createdAt: -1 })
                .toArray()

            const ids = saves
                .map((save) => {
                    const id = String(save.eventId)

                    if (!ObjectId.isValid(id)) {
                        return null
                    }

                    return new ObjectId(id);
                })
                .filter((id): id is ObjectId => id !== null)

            if (!ids.length) {
                return res.json({ events: [] });
            }

            const savedEvents = await events
                .find({
                    _id: { $in: ids },
                    date: { $gte: new Date() }
                })
                .sort({ date: 1 })
                .toArray()

            res.json({
                events: formatEvents(savedEvents, req.user!.email)
            })

        } catch (err: any) {
            res.status(500).json({
                message: err.message
            })
        }
    }
)

// SERVER
app.listen(port, async () => {
    try {
        await connectDB()

        console.log(
            `Simple CRUD Server is running on port: ${port}`
        )

    } catch (err: any) {
        console.log(
            `Failedd to connect MongoDB: ${err.message}`
        )
    }
})