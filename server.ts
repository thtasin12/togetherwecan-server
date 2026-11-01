import express, {
    type Express,
    type Request,
    type Response,
} from "express";

import { MongoClient } from "mongodb";
import "dotenv/config"
import cors from "cors"
import cookieParser from "cookie-parser";
import { error } from "node:console";

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

const connectDB = async () => {
    await client.connect()

    await users.createIndex({ email: 1 }, { unique: true });
    await events.createIndex({ date: 1 })
    await data.createIndex({ eventId: 1, userEmail: 1 }, { unique: true })
    await events.createIndex({ createdByEmail: 1 })

    console.log(`Database name ${db.databaseName}`)
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