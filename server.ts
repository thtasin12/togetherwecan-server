
import express, {
  type Express,
  type Request,
  type Response,
} from "express";



const app = express()
const port = process.env.PORT || 5000;



app.get('/', (req: Request, res: Response) => {
    res.send('Simple CRUD Server is running')
});

app.listen(port, () => {
    console.log(`Simple CRUD Server is running on port: ${port}`)
})